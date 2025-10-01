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

# [추가] 컨테이너 글로벌 기본 space. 요청 단위 space가 오면 그걸 최우선 사용.
CONF_SPACE = os.environ.get("CONFLUENCE_SPACE") or os.environ.get("CONF_DEFAULT_SPACE")

_OVERVIEW_HINTS = ["개요", "소개", "요약", "Overview", "Summary"]

def _normalize_ko_query(q: str) -> str:
    s = (q or "").strip()
    # 흔한 접두/메타 조각 제거
    s = re.sub(r"(?i)^query\s*:\s*history:?", " ", s)
    s = re.sub(r"(?i)^history\s*:\s*", " ", s)
    s = re.sub(r"[\"“”’‘'`]+", " ", s)
    # “~에 대해/대하여/관련” 같은 조사/연결어 날리기
    s = re.sub(r"\s*에\s*대(?:해|하여?)\s*", " ", s)
    s = re.sub(r"\s*관련\s*", " ", s)
    # 정중어/명령어 제거
    s = re.sub(r"(간단히|간단하게|좀|조금|자세히)\s*", " ", s)
    s = re.sub(r"(설명|알려|요약)\s*해\s*주(?:세요|실래요|나요|라|요)?", " ", s)
    s = re.sub(r"(설명|알려|요약)\s*해\s*줘(?:요)?", " ", s)
    s = re.sub(r"(무엇인가요|무엇인가요\?|뭔가요\?|뭐야\?|뭐야)", " ", s)
    # 공백 정리
    s = re.sub(r"\s+", " ", s).strip()
    return s

def _boost_overview(q: str) -> str:
    # “프로젝트” 언급이 있거나 질문형이면 개요 계열 키워드 추가 부스팅
    base = q
    if ("프로젝트" in q) or re.search(r"(개요|소개|요약|overview|summary)", q, re.I):
        extra = " ".join(_OVERVIEW_HINTS)
        base = f"{q} {extra}"
    return base

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
    # [TIP] space 힌트를 RAG로도 넘기려면 json에 "space": "XXX" 추가 가능(지금은 Confluence에만 적용)
    r = requests.post(f"{RAG}/query", json={"q": q, "k": k}, timeout=30)
    r.raise_for_status()
    return r.json() or {}

def rag_upsert_docs(docs):
    payload = {"docs": docs}
    # [수정] /documents/upsert 를 맨 앞에 두기(현재 rag-proxy에서 유효한 엔드포인트)
    for path in ["/documents/upsert", "/upsert", "/ingest", "/v1/upsert", "/v1/ingest"]:
        try:
            r = requests.post(f"{RAG}{path}", json=payload, timeout=120)
            if r.status_code < 300:
                return
        except Exception:
            pass
    raise HTTPException(500, "RAG upsert failed (no endpoint accepted JSON docs)")

# --- MCP HTTP Wrapper 유틸 ---
def mcp_conf_search(query: str, limit: int, space: Optional[str]) -> List[Dict[str, Any]]:
    # [변경] 요청 단위 space(우선) → 없으면 CONF_SPACE(글로벌 기본)
    eff_space = (space or "").strip() or CONF_SPACE
    payload = {"query": query, "limit": limit}
    if eff_space:
        payload["space"] = eff_space
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
    # [추가] 요청 단위로 space를 고정하고 싶을 때 사용 (없으면 환경변수 CONF_DEFAULT_SPACE/CONFLUENCE_SPACE)
    space: Optional[str] = None

@app.post("/search_and_ingest_mcp")
def search_and_ingest(req: SearchAndIngestReq):
    k  = req.top_k or TOP_K
    th = req.threshold if req.threshold is not None else THRESH
    q  = (req.query or "").strip()
    if not q:
        raise HTTPException(400, "query is empty")

    # [방지] 요약/제목생성 같은 메타 요청은 불필요한 외부 트래픽 차단
    if _is_meta_query(q):
        return {"used_fallback": False, "top_score": 1.0, "hits": []}

    q_norm = _normalize_ko_query(q)
    q_eff  = _boost_overview(q_norm)

    # 1) 1차 RAG 조회
    qres = rag_query(q_eff, k)

    items = qres.get("items") or qres.get("hits") or []
    def _best_score(xs):
        try: return max(float(x.get("score") or 0.0) for x in xs) if xs else 0.0
        except: return 0.0
    top_score = float(qres.get("top_score") or _best_score(items))

    used_fallback = False

    # [핵심] 폴백 조건: 히트가 없거나, 스코어 낮고 히트도 적을 때만
    need_fallback = (not items) or (top_score < th and len(items) < max(1, min(k, FALLBACK_MIN_HITS)))

    if need_fallback:
        # 2) MCP 검색 → 본문 수집 → 업서트
        found = mcp_conf_search(q_eff, limit=req.max_pages or k, space=req.space)  # ← space 전달
        new_docs: List[Dict[str, Any]] = []
        seen = set()  # 같은 page 중복 수집 방지

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
            # 3) 재조회 (여기선 원질문 q로 재조회해도 좋고, q_eff로 일관성 유지해도 됨)
            qres = rag_query(q, k)
            items = qres.get("items") or []
            top_score = float(qres.get("top_score") or _best_score(items))

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