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
TOP_K = int(os.environ.get("TOP_K", "12"))

# [CHANGE] 허위/일반지식 답변 억제를 위해 임계값 기본을 0.83으로 상향 권장
# [WHY] 0.7대는 헛컨텍스트 주입 위험. 0.8대가 안전.
THRESH = float(os.environ.get("THRESH", "0.83"))

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

# [ADD] 첨부 목록 조회 + OCR 텍스트 추출 호출
def mcp_conf_attachments(page_id: str, types: str = "pdf,img", limit: int = 10) -> List[Dict[str, Any]]:
    # [WHY] 표/스캔이 많은 페이지를 위해 첨부도 인덱싱
    r = requests.get(f"{MCP}/tool/attachments/{page_id}", params={"types": types, "limit": limit}, timeout=30)
    r.raise_for_status()
    return (r.json() or {}).get("items", []) or []

def mcp_conf_attachment_text(attachment_id: str, max_pages: Optional[int] = None) -> Dict[str, Any]:
    params = {"max_pages": max_pages} if max_pages else {}
    r = requests.get(f"{MCP}/tool/attachment_text/{attachment_id}", params=params, timeout=120)
    r.raise_for_status()
    return r.json() or {}

# --- API 모델 ---
class SearchAndIngestReq(BaseModel):
    query: str
    top_k: Optional[int] = None
    threshold: Optional[float] = None
    max_pages: Optional[int] = None  # MCP에서 최대 가져올 페이지 수

    # [ADD] 첨부 OCR 업서트 제어 옵션
    include_attachments: Optional[bool] = True          # 기본 on
    att_types: Optional[str] = "pdf,img"                # pdf,img | pdf | img
    att_limit: Optional[int] = 10                       # 첨부 최대 개수
    att_ocr_max_pages: Optional[int] = 3                # PDF 앞쪽 N페이지만 OCR

@app.post("/search_and_ingest_mcp")
async def search_and_ingest(req: SearchAndIngestReq):
    # [CHANGE] 스코어 해석 보강: score 우선, 없으면 distance를 유사도로 변환
    def _score_of(hit: Dict[str, Any]) -> float:
        try:
            if "score" in hit and hit["score"] is not None:
                return float(hit["score"])
            # 일부 백엔드는 distance만 줄 수 있음
            d = hit.get("distance")
            if d is None:
                return 0.0
            d = float(d)
            # 0~1 거리면 1-d, 그 외엔 1/(1+d)로 간이 변환
            return (1.0 - d) if 0.0 <= d <= 1.0 else 1.0 / (1.0 + d)
        except Exception:
            return 0.0

    def _best_score(xs):
        try:
            return max(_score_of(x) for x in xs) if xs else 0.0
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
                url   = (it.get("url") or "").strip()
                if not text:
                    continue

                new_docs.append({
                    "id": f"confluence:{pid}",
                    "text": text[:200_000],
                    "metadata": {
                        "source": "confluence",
                        "title": title,
                        "url": url,
                    }
                })

                # [ADD] 2-2-b 첨부 OCR 인덱싱 (옵션)
                if req.include_attachments:
                    try:
                        atts = mcp_conf_attachments(pid, types=(req.att_types or "pdf,img"),
                                                    limit=int(req.att_limit or 10)) or []
                    except Exception:
                        atts = []

                    for a in atts:
                        att_id = str(a.get("attachment_id") or "").strip()
                        if not att_id:
                            continue
                        try:
                            att = mcp_conf_attachment_text(att_id, max_pages=req.att_ocr_max_pages)
                        except Exception:
                            continue

                        att_text = (att.get("text") or "").strip()
                        if not att_text:
                            continue

                        att_title = (a.get("title") or att.get("title") or "").strip()
                        att_url   = (a.get("url") or att.get("url") or url or "").strip()

                        new_docs.append({
                            "id": f"confluence:{pid}:att:{att_id}",
                            "text": att_text[:200_000],
                            "metadata": {
                                "source": "confluence",
                                "title": f"{title} (첨부: {att_title})" if title else att_title,
                                "url": att_url,
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
        # [WHY] hits의 meta(title/url)는 위 업서트 metadata로 저장되어 재조회 시 함께 나옴
        return {
            "used_fallback": used_fallback,
            "top_score": float(top_score or 0.0),
            "hits": [
                {
                    "chunk": (h.get("text") or h.get("chunk") or "")[:1200],
                    "score": float(_score_of(h)),
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