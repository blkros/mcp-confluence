# mcp-confluence/main.py

import os, re
import typing as t
from urllib.parse import quote_plus
import httpx
from fastmcp import FastMCP

# ──────────────────────────────────────────────────────────────
# 환경변수
# ──────────────────────────────────────────────────────────────
BASE_URL    = (os.environ.get("CONFLUENCE_BASE_URL") or "").rstrip("/")
USER        = os.environ.get("CONFLUENCE_USER") or ""
PASSWORD    = os.environ.get("CONFLUENCE_PASSWORD") or ""
VERIFY_SSL  = (os.environ.get("VERIFY_SSL") or "true").lower() not in ("false", "0", "no")

if not BASE_URL:
    raise RuntimeError("CONFLUENCE_BASE_URL is not set")

CQL_MAX = 120
_CQL_BAD = re.compile(r'["\n\r\t]+')
_STOP = {"task","guidelines","output","chat","history","assistant","user",
         "제목","태그","대화","요약","가이드","출력"}

# Confluence Server/DC 표준 REST 경로
SEARCH_API_PRIMARY   = f"{BASE_URL}/rest/api/content/search"
SEARCH_API_FALLBACK  = f"{BASE_URL}/rest/api/search"
CONTENT_API          = f"{BASE_URL}/rest/api/content"

def page_view_url(page_id: str) -> str:
    return f"{BASE_URL}/pages/viewpage.action?pageId={page_id}"

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

# ──────────────────────────────────────────────────────────────
# Basic 먼저 → 401이면 폼 로그인(JSESSIONID) 폴백
# ──────────────────────────────────────────────────────────────
def get_confluence_client() -> httpx.Client:
    headers = {"Accept": "application/json"}

    # 1) Basic 먼저
    if USER and PASSWORD:
        c = httpx.Client(
            base_url=BASE_URL, headers=headers,
            auth=httpx.BasicAuth(USER, PASSWORD),
            verify=VERIFY_SSL, timeout=30.0
        )
        r = c.get("/rest/api/space?limit=1")
        if r.status_code != 401:
            return c  # Basic 성공
        c.close()

    # 2) 폼 로그인 폴백
    c = httpx.Client(
        base_url=BASE_URL, headers=headers,
        verify=VERIFY_SSL, timeout=30.0, follow_redirects=True
    )
    form = {
        "os_username": USER,
        "os_password": PASSWORD,
        "os_destination": "/",  # 로그인 성공 후 리다이렉트
    }
    c.post("/dologin.action", data=form, headers={"X-Atlassian-Token": "no-check"})
    # 세션 확인
    cr = c.get("/rest/api/space?limit=1")
    if cr.status_code == 401:
        c.close()
        raise RuntimeError("Confluence auth failed (Basic & Cookie both). Check policy/SSO.")
    return c

# ──────────────────────────────────────────────────────────────
# Tools
# ──────────────────────────────────────────────────────────────
# --- helpers -------------------------------------------------
def _html_to_text(html: str) -> str:
    import re
    txt = re.sub(r"<[^>]+>", " ", html or "")
    txt = re.sub(r"\s+", " ", txt).strip()
    return txt[:20000]  # 과도한 본문 제한

def get_cookie_client() -> httpx.Client:
    headers = {"Accept": "application/json"}
    c = httpx.Client(base_url=BASE_URL, headers=headers, verify=VERIFY_SSL, timeout=30.0, follow_redirects=True)
    form = {"os_username": USER, "os_password": PASSWORD, "os_destination": "/"}
    c.post("/dologin.action", data=form, headers={"X-Atlassian-Token": "no-check"})
    cr = c.get("/rest/api/space?limit=1")
    if cr.status_code == 401:
        c.close()
        raise RuntimeError("Confluence cookie auth failed. Check policy/SSO.")
    return c

# --- get_page: impl + tool wrapper ---------------------------
def _get_page_impl(page_id: str) -> dict:
    if not page_id:
        raise ValueError("page_id is required")
    pid = str(page_id)

    # 1) 쿠키 세션으로 REST 먼저 시도 (SSO 환경에서 성공률 ↑)
    c = get_cookie_client()
    try:
        url = f"{CONTENT_API}/{quote_plus(pid)}"
        params = {"expand": "body.storage,version,space"}
        r = c.get(url, params=params, headers={"Accept": "application/json"})
        ct = (r.headers.get("content-type") or "").lower()

        if r.status_code == 200 and "application/json" in ct:
            j = r.json() or {}
            body_html = ((j.get("body") or {}).get("storage") or {}).get("value", "") or ""
            return {
                "id": str(j.get("id") or pid),
                "title": j.get("title") or "",
                "space": ((j.get("space") or {}).get("key")) or "",
                "version": ((j.get("version") or {}).get("number")) or 0,
                "body_html": body_html,
                "url": page_view_url(str(j.get("id") or pid)),
            }
        # 200/JSON이 아니면 HTML 폴백으로 넘어감
    finally:
        c.close()

    # 2) HTML 폴백: viewstorage(본문) + viewpage(메타)
    c2 = get_cookie_client()
    try:
        # 2-1) 본문(storage format)
        r_body = c2.get(
            "/plugins/viewstorage/viewpagestorage.action",
            params={"pageId": pid},
            headers={"Accept": "text/html"},
            timeout=30.0,
        )
        body_html = r_body.text if r_body.status_code == 200 else ""

        # 2-2) 제목/스페이스/버전 (viewpage meta 태그 파싱)
        r_meta = c2.get(
            "/pages/viewpage.action",
            params={"pageId": pid},
            headers={"Accept": "text/html"},
            timeout=30.0,
        )
        title = ""
        space_key = ""
        version = 0
        if r_meta.status_code == 200:
            html = r_meta.text
            m = re.search(r'<meta\s+name="ajs-page-title"\s+content="([^"]*)"', html, re.I)
            if m: title = m.group(1).strip()
            m = re.search(r'<meta\s+name="ajs-space-key"\s+content="([^"]*)"', html, re.I)
            if m: space_key = m.group(1).strip()
            m = re.search(r'<meta\s+name="ajs-version-number"\s+content="(\d+)"', html, re.I)
            if m:
                try: version = int(m.group(1))
                except: version = 0

        if not (title or body_html):
            # HTML 폴백도 실패하면 명시적으로 에러
            raise RuntimeError(f"Page not accessible via REST/HTML: {pid}")

        return {
            "id": pid,
            "title": title or f"Page {pid}",
            "space": space_key,
            "version": version,
            "body_html": body_html,
            "url": page_view_url(pid),
        }
    finally:
        c2.close()

@app.tool()
def get_page(page_id: str) -> dict:
    return _get_page_impl(page_id)

# --- search_pages: impl + tool wrapper -----------------------
def _search_pages_impl(query: str, space: t.Optional[str] = None, limit: int = 10) -> t.List[dict]:
    text = _to_cql_text(query or "")
    if not text:
        return []

    def _cql_attempts(text: str, space: t.Optional[str]) -> t.List[str]:
        base_parts = ['type=page']
        if space:
            base_parts.append(f"space={space}")
        base = " AND ".join(base_parts)
        toks = [t for t in re.findall(r"[A-Za-z0-9가-힣]{2,}", text) if t.lower() not in _STOP][:4]
        attempts = [f'{base} AND (title ~ "{text}" OR text ~ "{text}")']
        if toks:
            attempts.append(base + " AND " + " AND ".join([f'text ~ "{t}"' for t in toks]))
            attempts.append(base + " AND (" + " OR ".join([f'title ~ "{t}"' for t in toks]) + ")")
        return attempts

    attempts = _cql_attempts(text, space)
    ENDPOINTS = (SEARCH_API_PRIMARY, SEARCH_API_FALLBACK)
    headers = {
        "X-Atlassian-Token": "no-check",
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json",
    }

    needs_cookie = False
    client = get_confluence_client()
    try:
        for cql in attempts:
            params = {"cql": cql, "limit": max(1, min(int(limit or 10), 50)), "expand": "space"}
            for endpoint in ENDPOINTS:
                r = client.get(endpoint, params=params, headers=headers, timeout=30.0)
                if r.status_code == 401:
                    raise RuntimeError("Confluence auth failed (401). Check USER/PASSWORD or SSO policy.")
                ct = (r.headers.get("content-type") or "").lower()
                if (r.status_code in (400, 403, 404, 501)) or ("application/json" not in ct):
                    continue
                data = r.json() or {}
                results = data.get("results") or []
                out = []
                for it in results:
                    content = (it or {}).get("content") or {}
                    page_id = str(content.get("id") or it.get("id") or "")
                    title = (content.get("title") or it.get("title") or "").strip()
                    excerpt = (it.get("excerpt") or "").strip()
                    if page_id and title:
                        out.append({"id": page_id, "title": title, "url": page_view_url(page_id), "excerpt": excerpt})
                if out:
                    return out
        # REST가 안 먹었음 → HTML 폴백 필요
        needs_cookie = (client.auth is not None)  # Basic이었으면 쿠키 필요
    finally:
        client.close()

    # HTML 폴백은 무조건 쿠키 세션 사용
    c2 = get_cookie_client()
    try:
        return _html_search_fallback(c2, query, space, limit)
    finally:
        c2.close()

@app.tool()
def search_pages(query: str, space: t.Optional[str] = None, limit: int = 10) -> t.List[dict]:
    items = _search_pages_impl(query, space, limit) or []
    # excerpt 비면 간단 보강
    if items:
        c = get_cookie_client()
        try:
            for it in items:
                if not (it.get("excerpt") or "").strip():
                    pid = it.get("id")
                    r = c.get("/plugins/viewstorage/viewpagestorage.action",
                              params={"pageId": pid}, headers={"Accept":"text/html"}, timeout=20.0)
                    if r.status_code == 200:
                        txt = _html_to_text(r.text)
                        it["excerpt"] = txt[:300]
        finally:
            c.close()
    return items

# --- search: RAG용(본문 포함) --------------------------------
@app.tool()
def search(
    query: str,
    top_k: int = 5,
    limit: t.Optional[int] = None,          # ← rag-proxy가 쓰는 이름도 허용
    space: t.Optional[str] = None
) -> t.List[dict]:
    # limit 우선, 없으면 top_k
    k = int(limit) if (isinstance(limit, int) and limit > 0) else int(top_k)

    items = _search_pages_impl(query=query, space=space, limit=k) or []
    out: t.List[dict] = []
    for it in items:
        pid = it.get("id")
        title = it.get("title") or ""
        url = it.get("url") or ""
        excerpt = it.get("excerpt") or ""

        body_txt = ""
        space_key = ""
        version = 0

        try:
            page = _get_page_impl(pid)
            if not title and page.get("title"):
                title = page["title"]
            body_html = page.get("body_html") or ""
            body_txt = _html_to_text(body_html)
            space_key = page.get("space") or ""
            version = page.get("version") or 0
        except Exception:
            # 본문 조회 실패 시에도 빈 문자열 방지: 발췌/제목으로라도 채움
            body_txt = excerpt or title or ""

        out.append({
            "id": pid,
            "title": title or f"Page {pid}",
            "url": url,
            "space": space_key,
            "version": version,
            "body": body_txt,   # ← rag-proxy가 읽는 키
            "text": body_txt,   # 호환
            "excerpt": excerpt,
        })
    return out


# 간단 HTML 태그 제거
def _strip_html(s: str) -> str:
    return re.sub(r"<[^>]+>", "", s or "").strip()

# /dosearchsite.action HTML 검색 폴백 (견고 버전)
def _html_search_fallback(client: httpx.Client, query: str, space: t.Optional[str], limit: int) -> t.List[dict]:
    text = _to_cql_text(query or "")
    if not text:
        return []

    params = {"queryString": text, "contentType": "page"}
    if space:
        params["where"] = "conf_space"
        params["spaceKey"] = space
    else:
        params["where"] = "conf_all"

    r = client.get(
        "/dosearchsite.action",
        params=params,
        headers={"Accept": "text/html"},
        timeout=30.0,
    )
    if r.status_code != 200 or "text/html" not in (r.headers.get("content-type") or "").lower():
        return []

    html = r.text

    # 1) 일단 pageId를 가장 단순한 패턴으로 모두 수집
    ids: t.List[str] = []
    for pid in re.findall(r'/pages/viewpage\.action\?pageId=(\d+)', html):
        if pid not in ids:
            ids.append(pid)
        if len(ids) >= max(1, min(int(limit or 10), 50)):
            break

    out: t.List[dict] = []
    for pid in ids:
        title = ""
        excerpt = ""

        # 2) 해당 pageId를 가진 앵커의 innerText 시도(따옴표 양쪽 다 허용)
        am = re.search(
            rf'<a[^>]+href=[\'"][^\'"]*/pages/viewpage\.action\?pageId={pid}[\'"][^>]*>(.*?)</a>',
            html, flags=re.I | re.S
        )
        if am:
            title = _strip_html(am.group(1))
            # 근처에서 발췌
            start = max(0, am.start() - 500)
            chunk = html[start:am.end() + 500]
            mm = re.search(
                r'(?:class="[^"]*(?:excerpt|summary|search-result[^"]*)[^"]*">)(.*?)(?:</(?:div|p)>)',
                chunk, flags=re.I | re.S
            )
            if mm:
                excerpt = _strip_html(mm.group(1))

        # 3) 앵커 텍스트가 없으면 REST로 제목 보강
        if not title:
            rr = client.get(f"{CONTENT_API}/{quote_plus(pid)}", params={"expand": "version,space"})
            ct = (rr.headers.get("content-type") or "").lower()
            if rr.status_code == 200 and "application/json" in ct:
                try:
                    title = (rr.json() or {}).get("title") or ""
                except Exception:
                    pass

        out.append({
            "id": pid,
            "title": title or f"Page {pid}",
            "url": page_view_url(pid),
            "excerpt": excerpt,
        })

    return out


if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "9000"))
    transport = os.getenv("TRANSPORT", "sse")  # 기본 sse
    app.run(transport=transport, host=host, port=port)