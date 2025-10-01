# bridge_mcp.py
# 목적: OWUI가 직접 호출하거나(있으면) rag-proxy가 내부 호출해서
#       1) RAG 1차 조회 -> 스코어 낮으면
#       2) MCP(Confluence HTTP wrapper) 검색/본문 수집 -> RAG 업서트 -> 재조회

import os, re, requests  # [# CHANGED] re 임포트 추가
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

# ※ 도커 네트워크 내부 호출은 서비스명 사용 권장
RAG   = os.environ.get("RAG_PROXY", "http://rag-proxy:8080").rstrip("/")
MCP   = os.environ.get("MCP_BASE",  "http://mcp-confluence:9001").rstrip("/")
TOP_K = int(os.environ.get("TOP_K", "5"))

# [# CHANGED] 기본 임계값을 낮추고(0.65 권장), 환경변수로 조절
THRESH= float(os.environ.get("THRESH", "0.65"))

# [# ADDED] 폴백을 훨씬 보수적으로: 스코어 낮고(hit도 적을 때)만
FALLBACK_MIN_HITS = int(os.environ.get("FALLBACK_MIN_HITS", "2"))  # hits가 너무 적을 때만 폴백

# [# ADDED] Confluence Space 강제 제한(HTTP wrapper에 전달)
CONF_SPACE = os.environ.get("CONFLUENCE_SPACE") or os.environ.get("CONF_DEFAULT_SPACE")

# [# ADDED] 메타 프롬프트/이력 덤프 차단 정규식
_META_PATTERNS = (
    r"^\s*###\s*task",            # ### Task:
    r"json\s*format",             # JSON format:
    r"<\s*chat_history\s*>",      # <chat_history>
    r"follow[-\s]*ups?",          # follow-up(s)
    r"title\s+with\s+an\s+emoji", # title with an emoji
    r"tags\s+categorizing",       # tags categorizing
    r"^query:\s*history",         # Query: History:
    r"^\s*history:",              # History:
)
def _is_meta_query(q: str) -> bool:
    s = (q or "").lower()
    return any(re.search(p, s) for p in _META_PATTERNS)

# --- RAG 유틸 ---
def rag_query(q: str, k: int) -> Dict[str, Any]:
    r = requests.post(f"{RAG}/query", json={"q": q, "k": k}, timeout=30)
    r.raise_for_status()
    return r.json() or {}

def rag_upsert_docs(docs):
    payload = {"docs": docs}
    tried, last = [], None
    for path in ["/upsert", "/ingest", "/v1/upsert", "/v1/ingest", "/documents/upsert"]:
        url = f"{RAG}{path}"
        try:
            r = requests.post(url, json=payload, timeout=120)
            tried.append(f"{path}:{r.status_code}")
            if r.status_code < 300:
                return
        except Exception as e:
            tried.append(f"{path}:EXC:{e}")
            last = str(e)
    raise HTTPException(500, f"RAG upsert failed. Tried={tried} last={last}")

# --- MCP HTTP Wrapper 유틸 ---
def mcp_conf_search(query: str, limit: int) -> List[Dict[str, Any]]:
    # [# CHANGED] space를 HTTP wrapper에 전달(서버 측에서 DEFAULT_SPACE 없을 수도 있으므로)
    payload = {"query": query, "limit": limit}
    if CONF_SPACE:  # [# ADDED]
        payload["space"] = CONF_SPACE  # [# ADDED]
    r = requests.post(f"{MCP}/tool/search", json=payload, timeout=30)
    r.raise_for_status()
    return (r.json() or {}).get("items", []) or []

def mcp_conf_page_text(page_id: str) -> Dict[str, Any]:
    r = requests.get(f"{MCP}/tool/page_text/{page_id}", timeout=30)
    r.raise_for_status()
    return r.json() or {}

# --- API 모델 ---
class SearchAndIngestReq(BaseModel):
    query: str
    top_k: Optional[int] = None
    threshold: Optional[float] = None
    max_pages: Optional[int] = None  # MCP에서 최대 가져올 페이지 수

@app.post("/search_and_ingest_mcp")
def search_and_ingest(req: SearchAndIngestReq):
    k  = req.top_k or TOP_K
    th = req.threshold if req.threshold is not None else THRESH
    q  = (req.query or "").strip()
    if not q:
        raise HTTPException(400, "query is empty")

    # [# ADDED] 메타 프롬프트/요약 생성류는 검색/폴백을 아예 수행하지 않음
    if _is_meta_query(q):  # [# ADDED]
        return {          # [# ADDED] 불필요한 Confluence 트래픽 차단
            "used_fallback": False,
            "top_score": 1.0,
            "hits": []
        }

    # 1) 1차 조회
    qres = rag_query(q, k)

    # rag-proxy 응답 호환: items(list), hits(int)
    items = []
    if isinstance(qres, dict):
        if isinstance(qres.get("items"), list):
            items = qres["items"]
        elif isinstance(qres.get("hits"), list):  # 구버전 호환
            items = qres["hits"]

    def _best_score(xs):
        try:
            return max(float(x.get("score") or 0.0) for x in xs) if xs else 0.0
        except Exception:
            return 0.0

    top_score = float(qres.get("top_score") or _best_score(items))

    used_fallback = False

    # [# CHANGED] 폴백 조건: (히트 없음) 또는 (스코어 낮고 히트도 적음) 일 때만
    need_fallback = (not items) or (top_score < th and len(items) < max(1, min(k, FALLBACK_MIN_HITS)))  # [# ADDED]

    if need_fallback:  # [# CHANGED]
        # 2) MCP 검색 → 본문 수집 → 업서트
        found = mcp_conf_search(q, limit=req.max_pages or k)
        new_docs: List[Dict[str, Any]] = []

        # [# ADDED] 단일 실행 내 중복 page 방지
        seen = set()

        for it in found:
            pid = it.get("page_id")
            if not pid or pid in seen:
                continue
            seen.add(pid)

            page = mcp_conf_page_text(pid)
            text  = (page.get("text") or "").strip()
            title = page.get("title") or it.get("title") or ""
            if not text:
                continue
            new_docs.append({
                "id": f"confluence:{pid}",
                "text": text[:200_000],
                "metadata": {
                    "source": "confluence",
                    "title": title,
                    "url": it.get("url") or "",
                }
            })

        if new_docs:
            rag_upsert_docs(new_docs)
            used_fallback = True
            # 3) 재조회
            qres = rag_query(q, k)
            items = qres.get("items") or []
            top_score = float(qres.get("top_score") or _best_score(items))

    # 4) 스니펫 반환 (items 기준으로 생성)
    return {
        "used_fallback": used_fallback,
        "top_score": top_score,
        "hits": [
            {
                "chunk": (h.get("text") or "")[:1200],
                "score": float(h.get("score") or 0.0),
                "meta":  h.get("metadata") or {}
            } for h in (items or [])
        ]
    }