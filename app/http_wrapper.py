# app/http_wrapper.py
# 목적: Confluence REST를 얇게 감싼 HTTP 엔드포인트 제공(/tool/search, /tool/page_text)
#      → 브릿지(bridge_mcp.py)에서 이걸 호출해서 검색/본문을 받아간다.

# --- [IMPORTS] ---
import os, re, time
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
DEFAULT_SPACE = os.getenv("CONF_DEFAULT_SPACE", "").strip() or None

if not BASE_URL:
    raise RuntimeError("CONFLUENCE_BASE_URL is not set")

# --- [CONST/UTILS] ---
SEARCH_API  = f"{BASE_URL}/rest/api/search"
CONTENT_API = f"{BASE_URL}/rest/api/content"
_YEAR_RE = re.compile(r'(?:19|20)\d{2}')

def _year_tokens(q: str) -> list[str]:
    years = _YEAR_RE.findall(q or "")
    out = []
    for y in years:
        out.append(y)
        out.append(f"{y}년")
    return out

def page_view_url(page_id: str) -> str:
    # Confluence Server/DC 공통 보기 URL
    return f"{BASE_URL}/pages/viewpage.action?pageId={page_id}"

# 세션(Basic Auth)
session = requests.Session()
session.auth   = (USER, PASSWORD)
session.verify = VERIFY_SSL
session.headers.update({"Accept": "application/json"})

# 키워드/질의 정제(너무 시끄러운 토큰 제거)
_STOP = {
    "task","guidelines","output","chat","history","assistant","user",
    "제목","태그","대화","요약","가이드","출력",
    "query","queries","질문","설명","설명해주세요","간단히","간단","해주세요","해줘"
}
_CQL_BAD  = re.compile(r'["\n\r\t]+')
CQL_MAX   = 120

DEBUG = (os.getenv("CONF_DEBUG") or "false").lower() in ("1","true","yes")

def dbg(*a):
    if DEBUG:
        print("[http_wrapper]", *a, flush=True)

def _keywords(s: str, max_terms: int = 6) -> str:
    toks = re.findall(r"[A-Za-z0-9가-힣]{2,}", s or "")
    toks = [t for t in toks if t.lower() not in _STOP]
    return " ".join(toks[:max_terms])

def _to_cql_text(q: str) -> str:
    q = _keywords(q) or (q or "")
    q = _CQL_BAD.sub(" ", q)
    q = re.sub(r"\s+", " ", q).strip()
    return q[:CQL_MAX]

def _to_cql_tokens(q: str, min_len: int = 2, max_tokens: int = 6):
    q = (q or "").strip()
    q = re.sub(r'["“”\'’]', ' ', q)
    toks = re.split(r'[\s\W]+', q)
    toks += _year_tokens(q)
    seen, out = set(), []
    for t in toks:
        t = t.strip()
        if len(t) >= min_len:
            key = t.lower()
            if key not in seen:
                out.append(t)
                seen.add(key)
            if len(out) >= max_tokens:
                break
    return out

def _browser_headers() -> dict:
    return {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "User-Agent": "Mozilla/5.0",
        "Referer": f"{BASE_URL}/dashboard.action",
        "Accept-Language": "ko,en;q=0.9",
    }

def _looks_like_login(html: str) -> bool:
    if not html: return False
    return bool(re.search(r'login|log-in|username|password', html, re.I))

def _html_search_fallback(sess: requests.Session, text: str, space: t.Optional[str], limit: int) -> dict:
    dbg("HTML_FALLBACK: start text=", text, "space=", space, "limit=", limit)    
    # if not space and DEFAULT_SPACE:
    #     space = DEFAULT_SPACE

    # 목적지(os_destination)로 로그인 쿠키를 얻기 위해 한 번 더 로그인
    search_path = "/dosearchsite.action"
    params = {"queryString": text, "contentType": "page"}
    if space:
        params.update({"where": "conf_space", "spaceKey": space})
        os_dest = f"/dosearchsite.action?queryString={quote_plus(text)}&contentType=page&where=conf_space&spaceKey={quote_plus(space)}"
    else:
        params.update({"where": "conf_all"})
        os_dest = f"/dosearchsite.action?queryString={quote_plus(text)}&contentType=page&where=conf_all"

    # 목적지 포함 로그인
    sess.post(f"{BASE_URL}/dologin.action",
              data={"os_username": USER, "os_password": PASSWORD, "os_destination": os_dest},
              allow_redirects=True, headers={"X-Atlassian-Token": "no-check"})

    last_r = None
    for i in range(3):
        r = sess.get(f"{BASE_URL}/dosearchsite.action", params=params,
                     headers=_browser_headers(), timeout=30, allow_redirects=True)
        last_r = r
        dbg("HTML_FALLBACK: /dosearchsite.action ->", r.status_code, r.headers.get("content-type"))

        if r.status_code == 200 and "text/html" in (r.headers.get("content-type") or "").lower():
            html = r.text or ""
            # 로그인 페이지 감지 시 재로그인 후 재시도
            if _looks_like_login(html):
                dbg("HTML_FALLBACK: looks like login page -> re-login and retry")
                sess = ensure_cookie_session()
                time.sleep(0.4 * (i + 1))
                continue
            ids = []
            for pid in re.findall(r'/pages/viewpage\.action\?pageId=(\d+)', html):
                if pid not in ids:
                    ids.append(pid)
                if len(ids) >= max(1, min(int(limit or 10), 50)):
                    break
            dbg("HTML_FALLBACK: found pageIds:", ids[:10], "(total", len(ids), ")")
    
            items = []
            for pid in ids:
                title = ""
                m = re.search(
                    rf'<a[^>]+href=[\'"][^\'"]*/pages/viewpage\.action\?pageId={pid}[\'"][^>]*>(.*?)</a>',
                    html, flags=re.I | re.S
                )
                if m:
                    title = _html_to_text(m.group(1))
                if not title:
                    rr = sess.get(f"{CONTENT_API}/{quote_plus(pid)}",
                                  params={"expand": "version,space"}, timeout=15)
                    if rr.status_code == 200 and "application/json" in (rr.headers.get("content-type","").lower()):
                        try:
                            title = (rr.json() or {}).get("title") or ""
                        except Exception:
                            pass

                excerpt = ""
                if m:
                    s = max(0, m.start() - 400)
                    chunk = html[s:m.end()+400]
                    mm = re.search(r'(?:class="[^"]*(?:excerpt|summary)[^"]*">)(.*?)(?:</(?:div|p)>)',
                                   chunk, flags=re.I | re.S)
                    if mm:
                        excerpt = _html_to_text(mm.group(1))[:300]

                items.append({"page_id": str(pid), "title": title or f"Page {pid}",
                              "url": page_view_url(pid), "excerpt": excerpt})
            dbg("HTML_FALLBACK: items:", len(items))
            return {"items": items}

        # 서버 에러/비-HTML이면 백오프 재시도
        dbg("HTML_FALLBACK: server err or non-html -> retry")
        time.sleep(0.6 * (i + 1))

    dbg("HTML_FALLBACK: final fail -> [] status=", getattr(last_r, "status_code", None))
    return {"items": []}

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
    text = re.sub(r"\n{3,}", "\n\n", text)
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
    space = (payload or {}).get("space") or DEFAULT_SPACE

    dbg("SEARCH: query=", query, "space=", space, "limit=", limit)

    # 1) 쿼리 정제
    text = _to_cql_text(query)
    if not text:
        dbg("SEARCH: empty after _to_cql_text -> return []")
        return {"items": []}

    tokens = _to_cql_tokens(text)
    
    parts = ['type=page']
    if tokens:
        title_or = " OR ".join([f'title ~ "{t}"' for t in tokens])
        text_and = " AND ".join([f'text ~ "{t}"' for t in tokens])
        parts.append("(" + " OR ".join([f'(title ~ "{t}" OR text ~ "{t}")' for t in tokens]) + ")")
    else:
        parts.append(f'(title ~ "{text}" OR text ~ "{text}")')
    if space:
        parts.append(f"space={space}")
    cql = " AND ".join(parts)
    dbg("CQL:", cql)

    params = {
        "cql": cql,
        "limit": max(1, min(limit, 50)),
        "expand": "space",
    }

    # --- REST 시도 + 쿠키 폴백, 실패/비-JSON이면 HTML 폴백 ---
    try:
        s = get_session_for_rest()
        r = s.get(SEARCH_API, params=params, timeout=30)
        ct = (r.headers.get("content-type") or "").lower()

        # [DEBUG] 1차 REST 호출 결과
        dbg("REST /search ->", r.status_code, ct, r.url)

        if r.status_code in (401, 403):
            dbg("REST 401/403 -> cookie login fallback")
            s = ensure_cookie_session()
            r = s.get(SEARCH_API, params=params, timeout=30)
            ct = (r.headers.get("content-type") or "").lower()
            dbg("REST(retry-cookie) /search ->", r.status_code, ct, r.url)

        if (not r.ok) or ("application/json" not in ct):
            dbg("FALLBACK: HTML dosearchsite.action (space=", space, ")")
            return _html_search_fallback(s, text, space, limit)

        js = r.json() or {}
        results = js.get("results") or []
        if space and not results:
            dbg("SEARCH: no hits in space, retry without space")
            cql_no_space = re.sub(r'\s+AND\s+space\s*=\s*\S+', '', cql)
            params_no_space = {**params, "cql": cql_no_space}
            r = s.get(SEARCH_API, params=params_no_space, timeout=30)
            if r.ok and "application/json" in (r.headers.get("content-type","").lower()):
                js = r.json() or {}
                results = js.get("results") or []

    except Exception as e:
        dbg("REST path exception:", repr(e), "-> try HTML fallback")
        try:
            s = ensure_cookie_session()
            return _html_search_fallback(s, text, space, limit)
        except Exception as e2:
            dbg("HTML fallback exception:", repr(e2))
            return {"items": []}

    results = js.get("results") or []
    items = []
    for res in results:
        content = (res.get("content") or {})
        if content.get("type") != "page":
            continue
        pid = str(content.get("id") or "")
        if not pid:
            continue
        title = content.get("title") or f"Page {pid}"
        excerpt = _html_to_text(res.get("excerpt") or "")[:300]
        items.append({"page_id": pid, "title": title, "url": page_view_url(pid), "excerpt": excerpt})
    dbg("SEARCH: REST items:", len(items))
    return {"items": items}

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

    # 먼저 ct 계산 + 1차 로그
    ct = (r.headers.get("content-type") or "").lower()
    dbg("PAGE_TEXT: REST ->", r.status_code, ct, url)

    # 401/403이면 쿠키 폴백
    if r.status_code in (401, 403, 404, 302) or "application/json" not in ct:
        dbg("PAGE_TEXT: cookie retry before viewstorage pageId=", page_id)
        s = ensure_cookie_session()
        r = s.get(url, params=params, timeout=30)
        ct = (r.headers.get("content-type") or "").lower()
        dbg("PAGE_TEXT: REST(retry-cookie) ->", r.status_code, ct, url)

    # REST가 404/403/302거나 JSON이 아니면 viewstorage 폴백
    ct = (r.headers.get("content-type") or "").lower()
    dbg("PAGE_TEXT: REST ->", r.status_code, ct, url)
    if r.status_code in (401, 403, 404, 302) or "application/json" not in ct:
        dbg("PAGE_TEXT: viewstorage fallback pageId=", page_id)
        # 목적지 포함 재로그인
        vs_path = f"/plugins/viewstorage/viewpagestorage.action?pageId={quote_plus(str(page_id))}&contentOnly=true"
        s = ensure_cookie_session()
        s.post(f"{BASE_URL}/dologin.action",
            data={"os_username": USER, "os_password": PASSWORD, "os_destination": vs_path},
            allow_redirects=True, headers={"X-Atlassian-Token":"no-check"})
        rr = s.get(f"{BASE_URL}/plugins/viewstorage/viewpagestorage.action",
                params={"pageId": page_id, "contentOnly": "true"},
                headers=_browser_headers(), timeout=30, allow_redirects=True)
        dbg("PAGE_TEXT: viewstorage ->", rr.status_code, rr.headers.get("content-type"))
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
            dbg("PAGE_TEXT: viewstorage ok. title(len)=", len(title), "text(len)=", len(text))
            return {"page_id": page_id, "title": title or f"Page {page_id}", "text": text[:200_000]}
        
        dbg("PAGE_TEXT: try REST export_view fallback")
        try:
            r2 = s.get(f"{BASE_URL}/rest/api/content/{quote_plus(str(page_id))}",
                       params={"expand": "body.export_view,title"},
                       timeout=30)
            if r2.ok and "application/json" in (r2.headers.get("content-type","").lower()):
                js2 = r2.json() or {}
                title2 = js2.get("title") or ""
                html2 = ((js2.get("body") or {}).get("export_view") or {}).get("value", "")
                text2 = _html_to_text(html2)
                dbg("PAGE_TEXT: export_view ok. title(len)=", len(title2), "text(len)=", len(text2))
                return {"page_id": page_id, "title": title2 or f"Page {page_id}", "text": text2[:200_000]}
        except Exception as ee:
            dbg("PAGE_TEXT: export_view exception:", repr(ee))

    # 기존 REST 성공 경로
    if r.status_code == 404:
        dbg("PAGE_TEXT: REST 404 final")
        raise HTTPException(404, "Confluence page not found")
    r.raise_for_status()
    js   = r.json() or {}
    title = js.get("title") or ""
    html  = ((js.get("body") or {}).get("storage") or {}).get("value", "")
    text  = _html_to_text(html)
    dbg("PAGE_TEXT: REST ok. title(len)=", len(title), "text(len)=", len(text))
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
    dbg("AUTH: ensure_cookie_session()")
    s = requests.Session()
    s.verify = VERIFY_SSL
    s.headers.update({"Accept": "application/json"})
    form = {"os_username": USER, "os_password": PASSWORD, "os_destination": "/", "login": "Log In"}
    s.post(f"{BASE_URL}/dologin.action", data=form, allow_redirects=True,
           headers={"X-Atlassian-Token": "no-check"})
    # 디버깅에 유용: 민감값은 출력 안 하고 키만 확인
    try:
        dbg("AUTH: cookie keys=", list(s.cookies.get_dict().keys()))
    except Exception:
        pass
    dbg("AUTH: cookie session ready")
    return s