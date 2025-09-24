# app/http_wrapper.py
# 목적: Confluence REST를 얇게 감싼 HTTP 엔드포인트 제공(/tool/search, /tool/page_text)
#      → 브릿지(bridge_mcp.py)에서 이걸 호출해서 검색/본문을 받아간다.

# --- [IMPORTS] ---
import os, re
import typing as t
import requests
from urllib.parse import quote, quote_plus
from fastapi import FastAPI, Body, HTTPException
from requests.utils import quote as _rquote

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

def _browser_headers() -> dict:
    return {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "User-Agent": "Mozilla/5.0",
        "Referer": f"{BASE_URL}/dashboard.action",
        "Accept-Language": "ko,en;q=0.9",
    }

def _html_search_fallback(sess: requests.Session, text: str, space: t.Optional[str], limit: int) -> dict:
    # 목적지(os_destination)로 로그인 쿠키를 얻기 위해 한 번 더 로그인
    search_path = "/dosearchsite.action"
    params = {"queryString": text, "contentType": "page"}
    if space:
        params["where"] = "conf_space"
        params["spaceKey"] = space
    else:
        params["where"] = "conf_all"

    # 목적지 포함 로그인
    form = {
        "os_username": USER,
        "os_password": PASSWORD,
        "os_destination": f"{search_path}?queryString={quote_plus(text)}&contentType=page&" + \
                          ("where=conf_space&spaceKey="+quote_plus(space) if space else "where=conf_all")
    }
    sess.post(f"{BASE_URL}/dologin.action", data=form, allow_redirects=True, headers={"X-Atlassian-Token":"no-check"})

    r = sess.get(f"{BASE_URL}{search_path}", params=params, headers=_browser_headers(), timeout=30, allow_redirects=True)
    if r.status_code != 200 or "text/html" not in (r.headers.get("content-type") or "").lower():
        return {"items": []}

    html = r.text
    ids = []
    for pid in re.findall(r'/pages/viewpage\.action\?pageId=(\d+)', html):
        if pid not in ids:
            ids.append(pid)
        if len(ids) >= max(1, min(int(limit or 10), 50)):
            break

    items = []
    for pid in ids:
        # 제목 캐치 (앵커 텍스트 주변)
        title = ""
        m = re.search(
            rf'<a[^>]+href=[\'"][^\'"]*/pages/viewpage\.action\?pageId={pid}[\'"][^>]*>(.*?)</a>',
            html, flags=re.I | re.S
        )
        if m:
            title = _html_to_text(m.group(1))
        if not title:
            # REST로 제목만 보강 (가능하면)
            rr = sess.get(f"{CONTENT_API}/{quote_plus(pid)}", params={"expand": "version,space"}, timeout=15)
            if rr.status_code == 200 and "application/json" in (rr.headers.get("content-type","").lower()):
                try:
                    title = (rr.json() or {}).get("title") or ""
                except Exception:
                    pass

        # 간단 발췌 보강
        excerpt = ""
        if m:
            s = max(0, m.start() - 400)
            chunk = html[s:m.end()+400]
            mm = re.search(r'(?:class="[^"]*(?:excerpt|summary)[^"]*">)(.*?)(?:</(?:div|p)>)',
                           chunk, flags=re.I | re.S)
            if mm:
                excerpt = _html_to_text(mm.group(1))[:300]

        items.append({
            "page_id": str(pid),
            "title": title or f"Page {pid}",
            "url": page_view_url(pid),
            "excerpt": excerpt
        })

    return {"items": items}

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

@api.post("/tool/search")
def tool_search(payload: dict = Body(...)):
    """
    입력: { "query": "...", "limit": 5, "space": "ENG"(옵션) }
    출력: { "items": [ {page_id, title, url, excerpt} ] }
    """
    query = (payload or {}).get("query", "")
    limit = int((payload or {}).get("limit", 5) or 5)
    space = (payload or {}).get("space")

    # 1) 쿼리 정제
    text = _to_cql_text(query)
    if not text:
        return {"items": []}

    # 2) CQL 구성
    parts = ['type=page', f'text ~ "{text}"']
    if space:
        parts.append(f"space={space}")
    cql = " AND ".join(parts)

    params = {
        "cql": cql,
        "limit": max(1, min(limit, 50)),
        "expand": "space",
    }

    # 3) Basic 먼저 시도
    s = get_session_for_rest()
    r = s.get(SEARCH_API, params=params, timeout=30)

    # 4) 401/403이면 쿠키 로그인 폴백
    if r.status_code in (401, 403):
        s = ensure_cookie_session()
        r = s.get(SEARCH_API, params=params, timeout=30)

    # 5) 여전히 실패/차단되면 HTML 검색 폴백
    if r.status_code in (401, 403, 302) or "application/json" not in (r.headers.get("content-type","").lower()):
        return _html_search_fallback(s, text, space, limit)

    if r.status_code == 400:
        return {"items": []}
    r.raise_for_status()

@api.get("/tool/page_text/{page_id}")
def tool_page_text(page_id: str):
    """
    출력: { page_id, title, text }
    """
    if not page_id:
        raise HTTPException(400, "page_id is required")

    url = f"{CONTENT_API}/{quote_plus(str(page_id))}"
    params = {"expand": "body.storage,title,version"}
    # 1) Basic 먼저
    s = get_session_for_rest()
    r = s.get(url, params=params, timeout=30)

    # 2) 401/403이면 쿠키 로그인 폴백
    if r.status_code in (401, 403):
        s = ensure_cookie_session()
        r = s.get(url, params=params, timeout=30)

    # [추가] REST가 404/403/302거나 JSON이 아니면 viewstorage 폴백
    ct = (r.headers.get("content-type") or "").lower()
    if r.status_code in (401, 403, 404, 302) or "application/json" not in ct:
        # 목적지 포함 재로그인
        vs_path = f"/plugins/viewstorage/viewpagestorage.action?pageId={quote_plus(str(page_id))}&contentOnly=true"
        s = ensure_cookie_session()
        s.post(f"{BASE_URL}/dologin.action",
            data={"os_username": USER, "os_password": PASSWORD, "os_destination": vs_path},
            allow_redirects=True, headers={"X-Atlassian-Token":"no-check"})
        rr = s.get(f"{BASE_URL}/plugins/viewstorage/viewpagestorage.action",
                params={"pageId": page_id, "contentOnly": "true"},
                headers=_browser_headers(), timeout=30, allow_redirects=True)
        if rr.status_code == 200 and "text/html" in (rr.headers.get("content-type","").lower()):
            html = rr.text
            text = _html_to_text(html)
            # 제목 보강
            tr = s.get(f"{BASE_URL}/pages/viewpage.action", params={"pageId": page_id},
                    headers=_browser_headers(), timeout=15, allow_redirects=True)
            title = ""
            if tr.status_code == 200:
                mm = re.search(r'<meta\s+name="ajs-page-title"\s+content="([^"]*)"', tr.text, re.I)
                if mm: title = mm.group(1).strip()
            return {"page_id": page_id, "title": title or f"Page {page_id}", "text": text[:200_000]}

    # 기존 REST 성공 경로
    if r.status_code == 404:
        raise HTTPException(404, "Confluence page not found")
    r.raise_for_status()
    js   = r.json() or {}
    title = js.get("title") or ""
    html  = ((js.get("body") or {}).get("storage") or {}).get("value", "")
    text  = _html_to_text(html)
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

# --- 세션 헬퍼: Basic 먼저, 401/403이면 폼 로그인으로 쿠키 세션 생성 ---
def get_session_for_rest() -> requests.Session:
    # 1) Basic으로 한 번 시도할 세션
    s = requests.Session()
    s.verify = VERIFY_SSL
    s.headers.update({"Accept": "application/json"})
    if USER and PASSWORD:
        s.auth = (USER, PASSWORD)
    return s

def ensure_cookie_session() -> requests.Session:
    """폼 로그인(JSESSIONID)으로 쿠키 세션 생성"""
    s = requests.Session()
    s.verify = VERIFY_SSL
    s.headers.update({"Accept": "application/json"})

    form = {
        "os_username": USER,
        "os_password": PASSWORD,
        "os_destination": "/",   # 로그인 후 리다이렉트 목적지
        "login": "Log In",       # 일부 테마/버전에서 필요
    }
    s.post(f"{BASE_URL}/dologin.action",
           data=form,
           allow_redirects=True,
           headers={"X-Atlassian-Token": "no-check"})
    return s