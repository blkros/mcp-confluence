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
# 간단 HTML 태그 제거
def _strip_html(s: str) -> str:
    return re.sub(r"<[^>]+>", "", s or "").strip()

# /dosearchsite.action HTML 검색 폴백
def _html_search_fallback(client: httpx.Client, query: str, space: t.Optional[str], limit: int) -> t.List[dict]:
    # 검색어 정제
    text = _to_cql_text(query or "")
    if not text:
        return []

    # 6.12 UI 검색 페이지 파라미터
    params = {
        "queryString": text,
        "contentType": "page",
    }
    if space:
        params["where"] = "conf_space"
        params["spaceKey"] = space
    else:
        params["where"] = "conf_all"

    # HTML로 내려오므로 Accept는 text/html
    r = client.get(
        "/dosearchsite.action",
        params=params,
        headers={"Accept": "text/html"},
        timeout=30.0,
    )
    if r.status_code != 200 or "text/html" not in (r.headers.get("content-type") or "").lower():
        return []

    html = r.text

    out: t.List[dict] = []
    seen = set()

    # 1) 결과 링크에서 pageId와 제목 추출
    #    예: <a href="/pages/viewpage.action?pageId=12345" ...>제목</a>
    for m in re.finditer(
        r'<a[^>]+href="[^"]*/pages/viewpage\.action\?pageId=(\d+)"[^>]*>(.*?)</a>',
        html, flags=re.I | re.S
    ):
        pid = m.group(1)
        title = _strip_html(m.group(2))
        if not pid or not title:
            continue
        if pid in seen:
            continue
        seen.add(pid)

        # 2) 근처에 스니펫(발췌) 있으면 추출 (여러 테마 대비, 느슨한 매칭)
        #    근처 500자 범위 안에서 'excerpt' / 'summary' 류 클래스 블록을 탐색
        start = max(0, m.start() - 500)
        chunk = html[start:m.end() + 500]
        ex = ""
        mm = re.search(
            r'(?:class="[^"]*(?:excerpt|summary|search-result[^"]*)[^"]*">)(.*?)(?:</(?:div|p)>)',
            chunk, flags=re.I | re.S
        )
        if mm:
            ex = _strip_html(mm.group(1))

        out.append({
            "id": pid,
            "title": title,
            "url": page_view_url(pid),
            "excerpt": ex,
        })

        if len(out) >= max(1, min(int(limit or 10), 50)):
            break

    return out

# JSON 가드 헬퍼
def _json_or_none(r):
    ct = (r.headers.get("content-type") or "").lower()
    if "application/json" not in ct:
        return None
    try:
        return r.json()
    except Exception:
        return None
    

def get_cookie_client() -> httpx.Client:
    headers = {"Accept": "application/json"}
    c = httpx.Client(
        base_url=BASE_URL, headers=headers,
        verify=VERIFY_SSL, timeout=30.0, follow_redirects=True
    )
    form = {
        "os_username": USER,
        "os_password": PASSWORD,
        "os_destination": "/",
    }
    c.post("/dologin.action", data=form, headers={"X-Atlassian-Token": "no-check"})
    # 로그인 확인 (401이면 실패)
    cr = c.get("/rest/api/space?limit=1")
    if cr.status_code == 401:
        c.close()
        raise RuntimeError("Confluence cookie auth failed. Check policy/SSO.")
    return c


@app.tool()
def search_pages(query: str, space: t.Optional[str] = None, limit: int = 10) -> t.List[dict]:
    """
    Confluence 검색 (6.12 호환):
      1) REST CQL (/rest/api/content/search → /rest/api/search 순서) 시도
      2) 403/HTML/빈결과면 UI 검색(/dosearchsite.action) HTML 파싱 폴백
    반환: [{id, title, url, excerpt}]
    """
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

    # 1) 우선 기존 로직대로 클라이언트 하나 생성(대개 Basic)
    client = get_confluence_client()
    try:
        # 1-1) REST 엔드포인트들로 CQL 순차 시도
        for cql in attempts:
            params = {
                "cql": cql,
                "limit": max(1, min(int(limit or 10), 50)),
                "expand": "space",
            }
            for endpoint in ENDPOINTS:
                r = client.get(endpoint, params=params, headers=headers, timeout=30.0)

                if r.status_code == 401:
                    raise RuntimeError("Confluence auth failed (401). Check USER/PASSWORD or SSO policy.")

                ct = (r.headers.get("content-type") or "").lower()
                is_json = "application/json" in ct
                if r.status_code in (400, 403, 404, 501) or not is_json:
                    # 다음 엔드포인트/다음 CQL로
                    continue

                data = r.json() or {}
                results = data.get("results") or []
                out: t.List[dict] = []
                for it in results:
                    content = (it or {}).get("content") or {}
                    page_id = str(content.get("id") or it.get("id") or "")
                    title = (content.get("title") or it.get("title") or "").strip()
                    excerpt = (it.get("excerpt") or "").strip()
                    if page_id and title:
                        out.append({
                            "id": page_id,
                            "title": title,
                            "url": page_view_url(page_id),
                            "excerpt": excerpt,
                        })
                if out:
                    return out

        # 2) REST가 막혔거나 결과가 비었으면 → HTML 폴백.
        #    이때 Basic 클라이언트면 쿠키가 없으므로 쿠키 세션으로 바꿔서 호출
        needs_cookie = (client.auth is not None)
    finally:
        client.close()

    if needs_cookie:
        client = get_cookie_client()
        try:
            return _html_search_fallback(client, query, space, limit)
        finally:
            client.close()
    else:
        # 이미 쿠키 세션이었다면 바로 폴백
        client = get_confluence_client()  # 쿠키 세션 재확보용
        try:
            return _html_search_fallback(client, query, space, limit)
        finally:
            client.close()

@app.tool()
def search(query: str, top_k: int = 5, space: t.Optional[str] = None) -> t.List[dict]:
    """
    Generic search tool for RAG proxies.
    Returns items with {id, title, url, excerpt, text} where `text` is plain text body for embedding.
    """
    # 1) 메타 검색
    items = search_pages(query=query, space=space, limit=top_k) or []

    # 2) 본문 가져와서 text 필드 채우기 (인덱싱용)
    out: t.List[dict] = []
    for it in items:
        pid = it.get("id")
        try:
            page = get_page(pid)
            # HTML → 텍스트 간단 변환 (개행/공백 정리, 너무 크면 자르기)
            body_html = page.get("body_html") or ""
            text = re.sub(r"<[^>]+>", " ", body_html)
            text = re.sub(r"\s+", " ", text).strip()
            if len(text) > 20000:
                text = text[:20000]
            out.append({
                **it,
                "text": text,
                "space": page.get("space") or "",
                "version": page.get("version") or 0,
            })
        except Exception:
            # 본문 실패해도 메타만이라도
            out.append({**it, "text": ""})
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

    # 폼로그인 폴백 클라이언트 사용
    client = get_confluence_client()
    try:
        r = client.get(url, params=params)
    finally:
        client.close()

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

    # 폼로그인 폴백 클라이언트 사용
    client = get_confluence_client()
    try:
        r = client.get(CONTENT_API, params=params)
    finally:
        client.close()

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
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "9000"))
    transport = os.getenv("TRANSPORT", "sse")  # 기본 sse
    app.run(transport=transport, host=host, port=port)
