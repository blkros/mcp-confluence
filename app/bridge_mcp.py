# bridge_mcp.py
# 목적: OWUI가 직접 호출하거나(있으면) rag-proxy가 내부 호출해서
#       1) RAG 1차 조회 -> 스코어 낮으면
#       2) MCP(Confluence HTTP wrapper) 검색/본문 수집 -> RAG 업서트 -> 재조회

import os, requests, asyncio
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.responses import JSONResponse

app = FastAPI()

# ※ 도커 네트워크 내부 호출은 서비스명 사용 권장
RAG   = os.environ.get("RAG_PROXY", "http://rag-proxy:8080").rstrip("/")
MCP   = os.environ.get("MCP_BASE",  "http://mcp-confluence:9001").rstrip("/")
TOP_K = int(os.environ.get("TOP_K", "8"))
THRESH = float(os.environ.get("THRESH", "0.73"))

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
    r = requests.post(f"{MCP}/tool/search", json={"query": query, "limit": limit}, timeout=30)
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
async def search_and_ingest(req: SearchAndIngestReq):
    def _best_score(xs):
        try:
            return max(float(x.get("score") or 0.0) for x in xs) if xs else 0.0
        except Exception:
            return 0.0

    k  = req.top_k or TOP_K
    th = req.threshold if req.threshold is not None else THRESH
    q  = (req.query or "").strip()
    print("[mcp] Q=", q, "k=", k, "th=", th, flush=True)

    # 절대 4xx/5xx 내보내지 않음
    if not q:
        return {"used_fallback": None, "top_score": 0.0, "hits": [], "error": "query is empty"}

    try:
        # 1) 1차 RAG 조회
        try:
            qres = rag_query(q, k) or {}
        except Exception as e:
            qres = {}

        items = []
        if isinstance(qres, dict):
            # rag-proxy 응답 호환: items(list) 또는 hits(list)
            items = qres.get("items") or qres.get("hits") or []

        top_score = float(qres.get("top_score") or _best_score(items))
        print("[mcp] first top_score=", top_score, "items=", len(items), flush=True)
        used_fallback = False

        # 2) 스코어가 임계치 미달이면 MCP로 보강
        if top_score < th:
            # 2-1) 검색 (간단 재시도)
            found = []
            for i in range(3):
                try:
                    found = mcp_conf_search(q, limit=(req.max_pages or k)) or []
                    break
                except Exception:
                    await asyncio.sleep(0.6 * (i + 1))
            if not isinstance(found, list):
                found = []
            print("[mcp] found (search) =", len(found), flush=True)
            # 2-2) 본문 수집 (간단 재시도)
            new_docs = []
            for it in found:
                pid = str(it.get("page_id") or it.get("id") or "").strip()
                if not pid:
                    continue

                page = {}
                for i in range(2):
                    try:
                        page = mcp_conf_page_text(pid) or {}
                        break
                    except Exception:
                        await asyncio.sleep(0.5 * (i + 1))

                text  = (page.get("text") or "").strip()
                title = (page.get("title") or it.get("title") or "").strip()
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
            print("[mcp] new_docs to upsert =", len(new_docs), flush=True)
            # 2-3) 업서트 & 재조회 (실패해도 무시)
            if new_docs:
                try:
                    rag_upsert_docs(new_docs)
                except Exception:
                    pass

                used_fallback = True

                try:
                    qres2 = rag_query(q, k) or {}
                    items = (qres2.get("items") or qres2.get("hits") or []) if isinstance(qres2, dict) else []
                    top_score = float(qres2.get("top_score") or _best_score(items))
                except Exception:
                    # 재조회 실패해도 200으로 종료
                    pass

        # 3) 최종 스니펫 반환 (항상 200)
        return {
            "used_fallback": used_fallback,
            "top_score": float(top_score or 0.0),
            "hits": [
                {
                    "chunk": (h.get("text") or h.get("chunk") or "")[:1200],
                    "score": float(h.get("score") or 0.0),
                    "meta":  (h.get("metadata") or h.get("meta") or {})
                } for h in (items or [])
            ]
        }

    except Exception as e:
        # 어떤 예외도 500으로 올리지 말고 200 + 빈 결과로 마무리
        return {
            "used_fallback": None,
            "top_score": 0.0,
            "hits": [],
            "error": str(e)
        }