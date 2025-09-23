# mcp-confluence/main.py
import os, re
import typing as t
import requests
from urllib.parse import quote_plus

from fastmcp import FastMCP

# ──────────────────────────────────────────────────────────────
# 환경변수
# ──────────────────────────────────────────────────────────────
BASE_URL = (os.environ.get("CONFLUENCE_BASE_URL") or "").rstrip("/")
USER = os.environ.get("CONFLUENCE_USER") or ""
PASSWORD = os.environ.get("CONFLUENCE_PASSWORD") or ""
VERIFY_SSL = (os.environ.get("VERIFY_SSL") or "true").lower() not in ("false", "0", "no")

if not BASE_URL:
    raise RuntimeError("CONFLUENCE_BASE_URL is not set")

CQL_MAX = 120
_CQL_BAD = re.compile(r'["\n\r\t]+')
_STOP = {"task","guidelines","output","chat","history","assistant","user",
         "제목","태그","대화","요약","가이드","출력"}

# Confluence Server(/Data Center) 표준 REST 경로
#   - 검색:        /rest/api/search?cql=...
#   - 콘텐츠 조회: /rest/api/content/{id}?expand=...
SEARCH_API = f"{BASE_URL}/rest/api/search"
CONTENT_API = f"{BASE_URL}/rest/api/content"

# 보기 URL (Confluence Server 기본)
def page_view_url(page_id: str) -> str:
    # Data Center/Server 공통적으로 동작하는 기본 보기 링크
    return f"{BASE_URL}/pages/viewpage.action?pageId={page_id}"

# 세션 (Basic Auth)
session = requests.Session()
session.auth = (USER, PASSWORD)
session.verify = VERIFY_SSL
session.headers.update({
    "Accept": "application/json",
})

# ──────────────────────────────────────────────────────────────
# FastMCP 앱
# ──────────────────────────────────────────────────────────────
app = FastMCP("Confluence MCP")

def _keywords(s: str, max_terms: int = 6) -> str:
    toks = re.findall(r"[A-Za-z0-9가-힣]{2,}", s or "")
    toks = [t for t in toks if t.lower() not in _STOP]
    return " ".join(toks[:max_terms])

def _to_cql_text(q: str) -> str:
    q = _keywords(q) or (q or "")
    q = _CQL_BAD.sub(" ", q)
    q = re.sub(r"\s+", " ", q).strip()
    return q[:CQL_MAX]

def _cql(query: str, space: t.Optional[str]) -> str:
    # CQL 예: type=page AND text ~ "foo" AND space=ENG
    parts = [ 'type=page', f'text ~ "{query}"' ]
    if space:
        parts.append(f"space={space}")
    return " AND ".join(parts)

@app.tool()
def search_pages(query: str, space: t.Optional[str] = None, limit: int = 10) -> t.List[dict]:
    """
    Confluence CQL 페이지 검색 (질의 정제 + 400 복구).
    반환: [{id, title, url, excerpt}]
    """
    text = _to_cql_text(query or "")
    if not text:
        return []

    parts = ['type=page', f'text ~ "{text}"']
    if space:
        parts.append(f"space={space}")
    cql = " AND ".join(parts)

    params = {
        "cql": cql,
        "limit": max(1, min(int(limit or 10), 50)),
        "expand": "space"
    }
    r = session.get(SEARCH_API, params=params, timeout=30)
    if r.status_code == 400:
        return []  # 오염된 질의 → 빈 결과로
    if r.status_code == 401:
        raise RuntimeError("Confluence auth failed (401). Check USER/PASSWORD or SSO policy.")
    if r.status_code == 403:
        raise RuntimeError("Confluence policy/permission (403).")
    r.raise_for_status()

    data = r.json() or {}
    results = data.get("results") or []

    out: t.List[dict] = []
    for it in results:
        content = (it or {}).get("content") or {}
        page_id = str(content.get("id") or "")
        title = content.get("title") or it.get("title") or ""
        excerpt = (it.get("excerpt") or "").strip()
        if page_id and title:
            out.append({
                "id": page_id,
                "title": title,
                "url": page_view_url(page_id),
                "excerpt": excerpt,
            })
    return out

@app.tool()
def get_page(page_id: str) -> dict:
    """
    페이지 ID로 본문(HTML)과 메타데이터를 조회.
    반환: {id, title, space, version, body_html, url}
    """
    if not page_id:
        raise ValueError("page_id is required")

    url = f"{CONTENT_API}/{quote_plus(str(page_id))}"
    params = {"expand": "body.storage,version,space"}
    r = session.get(url, params=params, timeout=30)
    if r.status_code == 401:
        raise RuntimeError("Confluence auth failed (401). Check USER/PASSWORD or SSO policy.")
    if r.status_code == 404:
        raise RuntimeError(f"Page not found: {page_id}")
    r.raise_for_status()

    j = r.json() or {}
    body_html = ""
    body = (j.get("body") or {}).get("storage") or {}
    if body.get("value"):
        body_html = body["value"]

    return {
        "id": str(j.get("id") or page_id),
        "title": j.get("title") or "",
        "space": ((j.get("space") or {}).get("key")) or "",
        "version": ((j.get("version") or {}).get("number")) or 0,
        "body_html": body_html,
        "url": page_view_url(str(j.get("id") or page_id)),
    }

@app.tool()
def get_page_by_title(space: str, title: str) -> dict:
    """
    스페이스 + 제목으로 단일 페이지 조회(가장 정확히 일치하는 것 1건).
    반환: {id, title, space, version, body_html, url}
    """
    if not space or not title:
        raise ValueError("space and title are required")

    params = {
        "title": title,
        "spaceKey": space,
        "expand": "body.storage,version,space",
        "limit": 1,
    }
    r = session.get(CONTENT_API, params=params, timeout=30)
    if r.status_code == 401:
        raise RuntimeError("Confluence auth failed (401). Check USER/PASSWORD or SSO policy.")
    r.raise_for_status()

    j = r.json() or {}
    results = j.get("results") or []
    if not results:
        raise RuntimeError(f"No page found: space={space}, title={title}")

    item = results[0]
    body_html = ""
    body = (item.get("body") or {}).get("storage") or {}
    if body.get("value"):
        body_html = body["value"]

    pid = str(item.get("id") or "")
    return {
        "id": pid,
        "title": item.get("title") or title,
        "space": ((item.get("space") or {}).get("key")) or space,
        "version": ((item.get("version") or {}).get("number")) or 0,
        "body_html": body_html,
        "url": page_view_url(pid),
    }

if __name__ == "__main__":
    import os
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "9000"))
    transport = os.getenv("TRANSPORT", "sse")  # 기본 sse
    app.run(transport=transport, host=host, port=port)
