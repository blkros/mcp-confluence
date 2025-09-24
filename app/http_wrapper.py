# app/http_wrapper.py
# 목적: Confluence REST를 얇게 감싼 HTTP 엔드포인트 제공(/tool/search, /tool/page_text)
#      → 브릿지(bridge_mcp.py)에서 이걸 호출해서 검색/본문을 받아간다.

# --- [IMPORTS] ---
import os, re
import typing as t
import requests
from urllib.parse import quote, quote_plus
from fastapi import FastAPI, Body, HTTPException

# --- [ENV] 기존 main.py와 동일 이름 사용 ---
BASE_URL = (os.environ.get("CONFLUENCE_BASE_URL") or "").rstrip("/")
USER = os.environ.get("CONFLUENCE_USER") or ""
PASSWORD = os.environ.get("CONFLUENCE_PASSWORD") or ""
VERIFY_SSL = (os.environ.get("VERIFY_SSL") or "true").lower() not in ("false", "0", "no")

if not BASE_URL:
    raise RuntimeError("CONFLUENCE_BASE_URL is not set")

# --- [CONST/UTILS] ---
SEARCH_API  = f"{BASE_URL}/rest/api/search"
CONTENT_API = f"{BASE_URL}/rest/api/content"

def page_view_url(page_id: str) -> str:
    # Confluence Server/DC 공통 보기 URL
    return f"{BASE_URL}/pages/viewpage.action?pageId={page_id}"

# 세션(Basic Auth)
session = requests.Session()
session.auth   = (USER, PASSWORD)
session.verify = VERIFY_SSL
session.headers.update({"Accept": "application/json"})

# 키워드/질의 정제(너무 시끄러운 토큰 제거)
_STOP = {"task","guidelines","output","chat","history","assistant","user",
         "제목","태그","대화","요약","가이드","출력"}
_CQL_BAD  = re.compile(r'["\n\r\t]+')
CQL_MAX   = 120

def _keywords(s: str, max_terms: int = 6) -> str:
    toks = re.findall(r"[A-Za-z0-9가-힣]{2,}", s or "")
    toks = [t for t in toks if t.lower() not in _STOP]
    return " ".join(toks[:max_terms])

def _to_cql_text(q: str) -> str:
    q = _keywords(q) or (q or "")
    q = _CQL_BAD.sub(" ", q)
    q = re.sub(r"\s+", " ", q).strip()
    return q[:CQL_MAX]

def _html_to_text(html: str) -> str:
    # 아주 라이트한 HTML→텍스트 변환 (필요하면 BeautifulSoup로 교체 가능)
    if not html:
        return ""
    text = (html.replace("</p>", "\n")
                .replace("<br/>", "\n")
                .replace("<br>", "\n")
                .replace("<li>", "- ")
                .replace("</li>", "\n"))
    text = re.sub(r"<[^>]+>", "", text)     # 태그 날리기
    text = re.sub(r"\n{3,}", "\n\n", text)  # 빈 줄 정리
    return text.strip()

# --- [FASTAPI APP] ---
api = FastAPI(title="Confluence HTTP Wrapper", version="1.0.0")

# --- [ENDPOINT] /tool/search : CQL 검색 ---
@api.post("/tool/search")
def tool_search(payload: dict = Body(...)):
    """
    입력: { "query": "...", "limit": 5, "space": "ENG"(옵션) }
    출력: { "items": [ {page_id, title, url, excerpt} ] }
    """
    query = (payload or {}).get("query", "")
    limit = int((payload or {}).get("limit", 5) or 5)
    space = (payload or {}).get("space")

    text = _to_cql_text(query)
    if not text:
        return {"items": []}

    parts = ['type=page', f'text ~ "{text}"']
    if space:
        parts.append(f"space={space}")
    cql = " AND ".join(parts)

    params = {
        "cql": cql,
        "limit": max(1, min(limit, 50)),
        "expand": "space"
    }
    _ensure_authenticated_session(session)
    r = session.get(SEARCH_API, params=params, timeout=30)
    if r.status_code == 400:
        return {"items": []}
    if r.status_code in (401, 403):
        raise HTTPException(r.status_code, f"Confluence auth/policy error ({r.status_code})")
    r.raise_for_status()

    data = r.json() or {}
    items = []
    for it in data.get("results") or []:
        content = (it or {}).get("content") or {}
        pid   = str(content.get("id") or "")
        title = content.get("title") or it.get("title") or ""
        excerpt = (it.get("excerpt") or "").strip()
        if pid and title:
            items.append({
                "page_id": pid,
                "title": title,
                "url": page_view_url(pid),
                "excerpt": excerpt
            })
    return {"items": items}

# --- [ENDPOINT] /tool/page_text/{page_id} : 본문(storage HTML→텍스트) ---
@api.get("/tool/page_text/{page_id}")
def tool_page_text(page_id: str):
    """
    출력: { page_id, title, text }
    """
    if not page_id:
        raise HTTPException(400, "page_id is required")

    url = f"{CONTENT_API}/{quote_plus(str(page_id))}"
    params = {"expand": "body.storage,title,version"}
    _ensure_authenticated_session(session)
    r = session.get(url, params=params, timeout=30)
    if r.status_code in (401, 404):
        raise HTTPException(r.status_code, f"Confluence error ({r.status_code})")
    r.raise_for_status()

    js   = r.json() or {}
    title = js.get("title") or ""
    html  = ((js.get("body") or {}).get("storage") or {}).get("value", "")
    text  = _html_to_text(html)
    # 안전상 텍스트 길이 제한
    return {"page_id": page_id, "title": title, "text": text[:200_000]}

# --- 쿠키 로그인 폴백 유틸 ---
def _ensure_authenticated_session(sess: requests.Session) -> requests.Session:
    """
    1) 먼저 REST 가벼운 엔드포인트(예: /rest/api/space?limit=1)로 Basic 시도
    2) 401/403이면 Basic을 끄고(/dologin.action)로 폼 로그인 → 쿠키 부여
    3) 쿠키 세션으로 다시 확인
    """
    # 1차: Basic으로 가볍게 확인
    try:
        r = sess.get(f"{BASE_URL}/rest/api/space", params={"limit": 1}, timeout=10)
        if r.status_code not in (401, 403):
            return sess  # Basic 통과
    except Exception:
        pass

    # 2차: 폼 로그인 (쿠키 세션으로 전환)
    sess.auth = None  # Basic 제거
    form = {"os_username": USER, "os_password": PASSWORD, "os_destination": "/"}
    sess.headers.update({"X-Atlassian-Token": "no-check"})
    lr = sess.post(f"{BASE_URL}/dologin.action", data=form, timeout=15, allow_redirects=True)

    # 3차: 쿠키가 실제로 유효한지 재확인
    cr = sess.get(f"{BASE_URL}/rest/api/space", params={"limit": 1}, timeout=10)
    if cr.status_code in (401, 403):
        raise HTTPException(cr.status_code, "Confluence auth/policy error (cookie fallback failed)")
    return sess