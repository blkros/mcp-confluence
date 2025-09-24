# mcp-confluence/main.py

import os, re, httpx, asyncio
import typing as t
from urllib.parse import quote_plus
from mcp.server.fastmcp import FastMCP
from .html_fallback import search_html

# ──────────────────────────────────────────────────────────────
# 환경변수
# ──────────────────────────────────────────────────────────────
BASE_URL    = (os.environ.get("CONFLUENCE_BASE_URL") or "").rstrip("/")
USER        = os.environ.get("CONFLUENCE_USER") or ""
PASSWORD    = os.environ.get("CONFLUENCE_PASSWORD") or ""
VERIFY_SSL  = (os.environ.get("VERIFY_SSL") or "true").lower() not in ("false", "0", "no")
TIMEOUT = int(os.getenv("HTTP_TIMEOUT","20"))

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

async def search_rest(query: str, limit: int = 5):
    auth = (USER, PASSWORD) if USER and PASSWORD else None
    async with httpx.AsyncClient(base_url=BASE_URL, follow_redirects=True, timeout=TIMEOUT, verify=VERIFY_SSL) as client:
        r = await client.get("/rest/api/search",
                             params={"cql": f'text~"{query}"', "expand":"content.body.storage","limit":limit},
                             auth=auth,
                             headers={"Accept":"application/json","X-Requested-With":"XMLHttpRequest"})
        if r.status_code != 200:
            return None
        data = r.json()
        out = []
        for it in (data.get("results") or [])[:limit]:
            cont = (it.get("content") or {})
            title = cont.get("title") or ""
            page_id = cont.get("id") or ""
            url = f"{BASE_URL}/pages/viewpage.action?pageId={page_id}" if page_id else BASE_URL
            # storage가 있으면 텍스트로, 없으면 HTML로 긁어옴
            storage = (((cont.get("body") or {}).get("storage") or {}).get("value") or "")
            if storage:
                from bs4 import BeautifulSoup
                body = BeautifulSoup(storage, "lxml").get_text("\n", strip=True)
            else:
                rp = await client.get(f"/pages/viewpage.action?pageId={page_id}")
                body = rp.text if rp.status_code == 200 else ""
                from .html_fallback import _clean_text
                body = _clean_text(body)
            if body.strip():
                out.append({"id": page_id, "space":"", "version":0, "title": title, "url": url, "body": body})
        return out

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
def _html_to_text(html: str) -> str:
    import re
    s = html or ""
    # 1) 통째 블록 제거
    s = re.sub(r"(?is)<(head|script|style|noscript|template)[\s\S]*?</\1>", " ", s)
    # 2) HTML 주석 제거
    s = re.sub(r"(?is)<!--.*?-->", " ", s)
    # 3) 줄바꿈 보존용 태그 치환
    s = re.sub(r"(?is)<br\s*/?>", "\n", s)
    s = re.sub(r"(?is)</p>", "\n", s)
    # 4) 나머지 태그 제거
    s = re.sub(r"<[^>]+>", " ", s)
    # 5) JS 전역/리소스 키 흔적 약간 정리(선택)
    s = re.sub(r"\b(WRM|AJS|window\.)[^\n]{0,200}", " ", s)
    # 6) 공백/줄 정리
    s = re.sub(r"[ \t]+\n", "\n", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    s = re.sub(r"[ \t]{2,}", " ", s)
    return s.strip()[:20000]


# [추가] 브라우저 흉내 헤더 유틸 (302 로그인 튕김 줄이는 데 도움)
def _browser_headers() -> dict:
    return {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "User-Agent": "Mozilla/5.0",
        "Referer": f"{BASE_URL}/dashboard.action",
        "Accept-Language": "ko,en;q=0.9",
    }

def get_cookie_client(destination: t.Optional[str] = None) -> httpx.Client:
    """
    목적지(os_destination) 페이지로 바로 리다이렉트되도록 로그인 쿠키를 받는다.
    permissionViolation(302 → /login.action) 완화 목적.
    """
    headers = {"Accept": "application/json"}
    c = httpx.Client(
        base_url=BASE_URL,
        headers=headers,
        verify=VERIFY_SSL,
        timeout=30.0,
        follow_redirects=True,
    )
    form = {
        "os_username": USER,
        "os_password": PASSWORD,
        "os_destination": (destination or "/"),
    }
    c.post("/dologin.action", data=form, headers={"X-Atlassian-Token": "no-check"})
    # 로그인 유효성 가볍게 확인
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
    # [변경] 목적지(path)를 만든 뒤, 그 목적지로 로그인해서 쿠키 세션 획득
    viewstorage_path = f"/plugins/viewstorage/viewpagestorage.action?pageId={pid}&contentOnly=true"
    c2 = get_cookie_client(destination=viewstorage_path)   # ← 핵심
    try:
        # 본문(storage format)
        r_body = c2.get(
            "/plugins/viewstorage/viewpagestorage.action",
            params={"pageId": pid, "contentOnly": "true"},
            headers=_browser_headers(),   # ← 브라우저 흉내 헤더
            timeout=30.0,
        )
        body_html = r_body.text if r_body.status_code == 200 else ""

        # 제목/스페이스/버전
        r_meta = c2.get(
            "/pages/viewpage.action",
            params={"pageId": pid},
            headers=_browser_headers(),
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

def _browser_headers() -> dict:
    return {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "User-Agent": "Mozilla/5.0",
        "Referer": f"{BASE_URL}/dashboard.action",
        "Accept-Language": "ko,en;q=0.9",
    }

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
                    r = c.get(
                        "/plugins/viewstorage/viewpagestorage.action",
                        params={"pageId": pid, "contentOnly": "true"},
                        headers={"Accept":"text/html"},
                        timeout=20.0
                    )
                    if r.status_code == 200:
                        txt = _html_to_text(r.text)
                        it["excerpt"] = txt[:300]
        finally:
            c.close()
    return items

def _safe_body_text_from_page_id(page_id: str) -> tuple[str, str, int, str]:
    """
    return (body_text, space_key, version, title)
    1) REST /rest/api/content/{id}?expand=body.storage,version,space 시도
    2) JSON이 아니거나 실패하면 /plugins/viewstorage/viewpagestorage.action?pageId=... (contentOnly) 폴백
    모두 실패하면 ("", "", 0, "")
    """
    # 1) REST 시도
    try:
        client = get_confluence_client()
        try:
            url = f"{CONTENT_API}/{quote_plus(str(page_id))}"
            r = client.get(url, params={"expand": "body.storage,version,space"}, timeout=30)
        finally:
            client.close()

        ct = (r.headers.get("content-type") or "").lower()
        if r.status_code == 401:
            raise RuntimeError("401")
        if "application/json" in ct:
            j = r.json() or {}
            body_html = ((j.get("body") or {}).get("storage") or {}).get("value", "") or ""
            title = j.get("title") or ""
            space_key = ((j.get("space") or {}).get("key")) or ""
            version = ((j.get("version") or {}).get("number")) or 0
            if body_html.strip():
                return _html_to_text(body_html), space_key, version, title
        # JSON이 아니면 로그인/리다이렉트일 가능성 → 폴백으로
    except Exception:
        pass

    # 2) viewstorage 폴백 (쿠키 세션)
    try:
        viewstorage_path = f"/plugins/viewstorage/viewpagestorage.action?pageId={page_id}&contentOnly=true"
        c = get_cookie_client(destination=viewstorage_path)
        try:
            r = c.get(
                "/plugins/viewstorage/viewpagestorage.action",
                params={"pageId": page_id, "contentOnly": "true"},
                headers=_browser_headers(),
                timeout=30,
            )
            if r.status_code == 200 and "text/html" in (r.headers.get("content-type","").lower()):
                return _html_to_text(r.text), "", 0, ""
        finally:
            c.close()
    except Exception:
        pass

    return "", "", 0, ""

# --- search: RAG용(본문 포함) --------------------------------
@app.tool()
def search(
    query: str,
    top_k: int = 5,
    limit: t.Optional[int] = None,
    space: t.Optional[str] = None
) -> t.List[dict]:
    k = int(limit) if (isinstance(limit, int) and limit > 0) else int(top_k)
    items = _search_pages_impl(query=query, space=space, limit=k) or []
    out: t.List[dict] = []

    for it in items:
        pid = it.get("id")
        title = it.get("title") or ""
        url = it.get("url") or ""
        excerpt = (it.get("excerpt") or "").strip()

        body_txt, space_key, version, title2 = _safe_body_text_from_page_id(pid)
        if (not title) and title2:
            title = title2
        if not body_txt:
            # 본문이 비면 발췌/제목이라도
            body_txt = excerpt or title or ""

        out.append({
            "id": pid,
            "title": title or f"Page {pid}",
            "url": url,
            "space": space_key,
            "version": version,
            "body": body_txt,
            "text": body_txt,
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

    # 검색 경로 + 쿼리스트링을 os_destination 으로 주고 재로그인
    search_path = "/dosearchsite.action"
    from httpx import QueryParams
    destination = f"{search_path}?{str(QueryParams(params))}"
    c = get_cookie_client(destination=destination)
    r = c.get(
        search_path,
        params=params,
        headers=_browser_headers(),
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
    app.run()