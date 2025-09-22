# bridge_mcp.py
# 목적: OWUI가 직접 호출하거나(있으면) rag-proxy가 내부 호출해서
#       1) RAG 1차 조회 -> 스코어 낮으면
#       2) MCP(Confluence HTTP wrapper) 검색/본문 수집 -> RAG 업서트 -> 재조회

import os, requests
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

# ※ 도커 네트워크 내부 호출은 서비스명 사용 권장
RAG   = os.environ.get("RAG_PROXY", "http://rag-proxy:8080").rstrip("/")
MCP   = os.environ.get("MCP_BASE",  "http://mcp-confluence:9001").rstrip("/")
TOP_K = int(os.environ.get("TOP_K", "5"))
THRESH= float(os.environ.get("THRESH", "0.83"))

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
def search_and_ingest(req: SearchAndIngestReq):
    k  = req.top_k or TOP_K
    th = req.threshold if req.threshold is not None else THRESH
    q  = (req.query or "").strip()
    if not q:
        raise HTTPException(400, "query is empty")

    # 1) 1차 조회
    qres = rag_query(q, k)
    hits = qres.get("hits", []) or []
    top_score = qres.get("top_score")
    if top_score is None and hits:
        top_score = hits[0].get("score", 0.0)
    top_score = float(top_score or 0.0)

    used_fallback = False
    if top_score < th:
        # 2) MCP 검색 → 본문 수집 → 업서트
        items = mcp_conf_search(q, limit=req.max_pages or k)
        new_docs: List[Dict[str, Any]] = []
        for it in items:
            pid = it.get("page_id")
            if not pid:
                continue
            page = mcp_conf_page_text(pid)
            text  = (page.get("text") or "").strip()
            title = page.get("title") or it.get("title") or ""
            if not text:
                continue
            new_docs.append({
                "id": f"confluence:{pid}",
                "text": text[:200_000],  # 안전상 길이 제한
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
            hits = qres.get("hits", []) or []
            top_score = qres.get("top_score")
            if top_score is None and hits:
                top_score = hits[0].get("score", 0.0)
            top_score = float(top_score or 0.0)

    # 4) 스니펫 반환
    return {
        "used_fallback": used_fallback,
        "top_score": top_score,
        "hits": [
            {
                "chunk": (h.get("text") or "")[:1200],
                "score": float(h.get("score") or 0.0),
                "meta":  h.get("metadata") or {}
            } for h in hits
        ]
    }
