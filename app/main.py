# mcp-confluence/main.py

import os, re, httpx
import typing as t
from urllib.parse import quote_plus
from mcp.server.fastmcp import FastMCP

# ──────────────────────────────────────────────────────────────
# 환경변수
# ──────────────────────────────────────────────────────────────
BASE_URL    = (os.environ.get("CONFLUENCE_BASE_URL") or "").rstrip("/")
USER        = os.environ.get("CONFLUENCE_USER") or ""
PASSWORD    = os.environ.get("CONFLUENCE_PASSWORD") or ""
VERIFY_SSL  = (os.environ.get("VERIFY_SSL") or "true").lower() not in ("false", "0", "no")
TIMEOUT = int(os.getenv("HTTP_TIMEOUT","20"))
# DEFAULT_SPACE   = os.getenv("CONFLUENCE_SPACE", "SMST")  # 기본 스코프
RAW_SPACES = os.getenv("CONFLUENCE_SPACE", "").strip()
CONFLUENCE_SPACES = [s.strip() for s in re.split(r"[,\s]+", RAW_SPACES) if s.strip()]
DEFAULT_SPACE = CONFLUENCE_SPACES[0] if CONFLUENCE_SPACES else ""
DEFAULT_ANCESTOR = os.getenv("CONFLUENCE_ANCESTOR", "")  # 선택(루트 pageId)

# HTML 검색(사이트 검색) 폴백 끄기/켜기
USE_HTML_FALLBACK = (
    os.getenv("ENABLE_SITE_SEARCH","").lower() in ("1","true","yes")
    or os.getenv("SITE_SEARCH_FALLBACK","").lower() in ("1","true","yes")
    or os.getenv("USE_HTML_SEARCH","").lower() in ("1","true","yes")
)

# --- add: Korean stopwords & normalizer --------------------------------
_KO_STOP = {
    "에서","에","에게","으로","로","을","를","이","가","은","는","와","과",
    "대한","대해서","관해","관련","소개","설명","정리","알려줘","해줘","해주세요",
    "컨플루언스에서","컨플루언스"
}
_KO_POSTFIX = re.compile(r"(에서|으로|로|에게|에|은|는|이|가|을|를)$")

def _norm_ko_tokens(s: str) -> t.List[str]:
    toks = re.findall(r"[A-Za-z0-9가-힣]{2,}", s or "")
    out = []
    for t in toks:
        tl = t.lower()
        if tl in _STOP or tl in _KO_STOP:
            continue
        # 조사 꼬리 제거: 프로젝트에 -> 프로젝트
        t2 = _KO_POSTFIX.sub("", t)
        if t2:
            out.append(t2)
    return out

def _guess_title(q: str) -> t.Optional[str]:
    q = q.replace("프로젝트에", "프로젝트")
    m = re.search(r'([A-Za-z0-9가-힣]+)\s*프로젝트', q)
    if m:
        return f'{m.group(1)} 프로젝트'
    if "NIA" in q and "프로젝트" in q:
        return "NIA 프로젝트"
    return None


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

def _is_allowed_space(space_key: str) -> bool:
    if not CONFLUENCE_SPACES:   # 지정 안 했으면 전부 허용
        return True
    return (space_key or "").upper() in {s.upper() for s in CONFLUENCE_SPACES}

def _parse_spaces(space: t.Optional[str]) -> t.List[str]:
    """
    요청에서 space가 와도, 환경변수 CONFLUENCE_SPACE와 합집합으로 취급한다.
    (rag-proxy가 NTRP만 넘겨도 SMST,NTRP 둘 다 검색되게)
    """
    base = CONFLUENCE_SPACES[:]  # env 허용 스페이스들, 예: ["SMST","NTRP"]
    req = []
    if space and space.strip():
        req = [s.strip() for s in re.split(r"[,\s]+", space) if s.strip()]

    out = []
    for x in (req + base):
        if x and x not in out:
            out.append(x)
    return out


# ──────────────────────────────────────────────────────────────
# FastMCP 앱
# ──────────────────────────────────────────────────────────────
# app = FastMCP("Confluence MCP")
mcp = FastMCP("Confluence MCP") 

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
    text = _to_cql_text(query)
    auth = (USER, PASSWORD) if USER and PASSWORD else None
    async with httpx.AsyncClient(base_url=BASE_URL, follow_redirects=True, timeout=TIMEOUT, verify=VERIFY_SSL) as client:
        r = await client.get("/rest/api/search",
                             params={"cql": f'text~"{text}"', "expand":"content.body.storage","limit":limit},
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
        if r.status_code not in (401, 403):
            return c  # OK
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
            space_key = ((j.get("space") or {}).get("key")) or ""
            if not _is_allowed_space(space_key):
                c.close()
                raise RuntimeError(f"Blocked by space guard (expected {DEFAULT_SPACE}, got {space_key})")
            
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

        if not _is_allowed_space(space_key):
            c2.close()
            raise RuntimeError(f"Blocked by space guard (expected {DEFAULT_SPACE}, got {space_key or 'UNKNOWN'})")
        
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

@mcp.tool()
def get_page(page_id: str) -> dict:
    return _get_page_impl(page_id)

# --- search_pages: impl + tool wrapper -----------------------
def _search_pages_impl(query: str, space: t.Optional[str] = None, limit: int = 10) -> t.List[dict]:
    needs_cookie = False
    had_json_attempt = False  # JSON 응답을 한 번이라도 받았는지 플래그
    
    text = _to_cql_text(query or "")
    if not text:
        return []
    
    spaces = _parse_spaces(space)
    ancestor = (DEFAULT_ANCESTOR or "").strip()

    def _space_clause(spaces: t.List[str]) -> str:
        if not spaces:
            return ""  # 스페이스 필터 없음
        if len(spaces) == 1:
            return f'space="{spaces[0]}"'
        joined = ", ".join(f'"{s}"' for s in spaces)
        return f"space in ({joined})"

    def _cql_attempts(text: str) -> t.List[str]:
        base_parts = ['type=page']
        sc = _space_clause(spaces)
        if sc:
            base_parts.append(sc)
        if ancestor.isdigit():
            base_parts.append(f"ancestor={ancestor}")
        base = " AND ".join(base_parts)

        # 기존 1차: 문장 전체(현행 유지)
        attempts: t.List[str] = [f'{base} AND (title ~ "{text}" OR text ~ "{text}")']

        # 2차: 제목 추정 직격
        g = _guess_title(text)
        if g:
            attempts.append(f'{base} AND title ~ "{g}"')

        # 3차: 핵심 토큰 기반(한국어 조사 제거)
        toks = _norm_ko_tokens(text)[:4]
        if toks:
            # must(AND): 영문/숫자 또는 도메인 키워드 우선 1~2개
            must: t.List[str] = []
            for tkn in toks:
                if tkn.isascii() or tkn in {"프로젝트","계획","개요","요구사항","보고서"}:
                    must.append(tkn)
                if len(must) >= 2:
                    break
            if not must:
                must = toks[:1]

            # 3-1) must AND
            attempts.append(base + " AND " + " AND ".join([f'text ~ "{t}"' for t in must]))
            # 3-2) 제목 OR 토큰
            attempts.append(base + " AND (" + " OR ".join([f'title ~ "{t}"' for t in toks]) + ")")

        return attempts

    attempts = _cql_attempts(text)
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
                had_json_attempt = True
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
                
        # REST가 전부 0건이면(그리고 JSON을 한 번이라도 받았으면) limit 상향 재시도
        if had_json_attempt and 1 <= int(limit or 10) < 12:
            new_limit = 15  # 12~20 선호
            for cql in attempts:
                for endpoint in ENDPOINTS:
                    r = client.get(endpoint, params={"cql": cql, "limit": new_limit, "expand": "space"},
                                headers=headers, timeout=30.0)
                    ct = (r.headers.get("content-type") or "").lower()
                    if r.status_code in (400,403,404,501) or "application/json" not in ct:
                        continue
                    data = r.json() or {}
                    results = data.get("results") or []
                    out2 = []
                    for it in results:
                        content = (it or {}).get("content") or {}
                        page_id = str(content.get("id") or it.get("id") or "")
                        title = (content.get("title") or it.get("title") or "").strip()
                        excerpt = (it.get("excerpt") or "").strip()
                        if page_id and title:
                            out2.append({"id": page_id, "title": title, "url": page_view_url(page_id), "excerpt": excerpt})
                    if out2:
                        return out2

        # REST가 안 먹었음 → HTML 폴백 필요
        needs_cookie = (client.auth is not None)  # Basic이었으면 쿠키 필요
    finally:
        client.close()

    # REST 실패 시: HTML 폴백은 env가 true일 때만
    if USE_HTML_FALLBACK:
        c2 = get_cookie_client()
        try:
            return _html_search_fallback(c2, query, space, limit)
        finally:
            c2.close()
    else:
        return []

@mcp.tool()
def search_pages(query: str, space: t.Optional[str] = None, limit: int = 10) -> t.List[dict]:
    try:
        items = _search_pages_impl(query, space, limit) or []
    except Exception as e:
        print(f"[mcp] search_pages error: {e}", flush=True)
        return []
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
@mcp.tool()
def search(
    query: str,
    top_k: int = 5,
    limit: t.Optional[int] = None,
    space: t.Optional[str] = None
) -> t.List[dict]:
    try:
        k = int(limit) if (isinstance(limit, int) and limit > 0) else int(top_k)
        # space = space or DEFAULT_SPACE
        items = _search_pages_impl(query=query, space=space, limit=k) or []
        out: t.List[dict] = []
    except Exception as e:
        print(f"[mcp] search error: {e}", flush=True)
        return []
    
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

def _html_search_fallback(client: httpx.Client, query: str, space: t.Optional[str], limit: int) -> t.List[dict]:
    text = _to_cql_text(query or "")
    if not text:
        return []

    spaces = _parse_spaces(space)
    search_path = "/dosearchsite.action"

    def _one_space(space_key: str) -> t.List[dict]:
        params = {"queryString": text, "contentType": "page"}
        if space_key:
            params.update({"where": "conf_space", "spaceKey": space_key})
        else:
            params.update({"where": "conf_all"})

        from httpx import QueryParams
        destination = f"{search_path}?{str(QueryParams(params))}"
        c = get_cookie_client(destination=destination)
        try:
            r = c.get(search_path, params=params, headers=_browser_headers(), timeout=30.0)
        finally:
            c.close()
        if r.status_code != 200 or "text/html" not in (r.headers.get("content-type") or "").lower():
            return []

        html = r.text
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
            # 제목/발췌 추출 로직(기존 그대로) ...
            # (생략) ─ 기존 코드 블록 재사용
            out.append({"id": pid, "title": title or f"Page {pid}", "url": page_view_url(pid), "excerpt": excerpt})
        return out

    # 다중 스페이스 합집합 수집 + 중복 제거
    seen, merged = set(), []
    base_spaces = spaces if spaces else [""]
    for sk in base_spaces:
        chunk = _one_space(sk)
        for it in chunk:
            pid = it.get("id")
            if pid and pid not in seen:
                seen.add(pid)
                merged.append(it)
                if len(merged) >= max(1, min(int(limit or 10), 50)):
                    return merged
    return merged


# mcp-confluence/main.py (하단)
from fastapi import FastAPI

api = FastAPI()

@api.get("/health")
def health():
    return {"status": "ok", "base_url": BASE_URL}

# FIX: 클라이언트 기본값(/sse)에 맞춤
api.mount("/", mcp.sse_app())

if __name__ == "__main__":
    import os, uvicorn
    port = int(os.getenv("FASTMCP_PORT", "9000"))
    uvicorn.run(api, host="0.0.0.0", port=port)

# --- Debug/HTTP mirror of MCP tools (for curl testing) ---
from fastapi import Body

@api.post("/tool/search")
def http_tool_search(payload: dict = Body(...)):
    query = (payload or {}).get("query", "")
    limit = int((payload or {}).get("limit", 5) or 5)
    space = (payload or {}).get("space")
    # 내부 MCP 도구 로직 재사용
    items = search(query=query, top_k=limit, limit=limit, space=space)  # returns list[dict]
    return {"items": items}

@api.get("/tool/page_text/{page_id}")
def http_tool_page_text(page_id: str):
    info = _get_page_impl(page_id)  # { id, title, space, version, body_html, url }
    text = _html_to_text(info.get("body_html", ""))
    return {
        "page_id": info.get("id"),
        "title": info.get("title"),
        "space": info.get("space"),
        "url": info.get("url"),
        "text": text,
    }