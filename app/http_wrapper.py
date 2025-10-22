# app/http_wrapper.py
# 목적: Confluence REST를 얇게 감싼 HTTP 엔드포인트 제공(/tool/search, /tool/page_text)
#      → 브릿지(bridge_mcp.py)에서 이걸 호출해서 검색/본문을 받아간다.

# --- [IMPORTS] ---
import os, re
import typing as t
import requests
from urllib.parse import quote, quote_plus
from fastapi import FastAPI, Body, HTTPException
# from requests.utils import quote as _rquote

# --- [ENV] 기존 main.py와 동일 이름 사용 ---
BASE_URL = (os.environ.get("CONFLUENCE_BASE_URL") or "").rstrip("/")
USER = os.environ.get("CONFLUENCE_USER") or ""
PASSWORD = os.environ.get("CONFLUENCE_PASSWORD") or ""
VERIFY_SSL = (os.environ.get("VERIFY_SSL") or "true").lower() not in ("false", "0", "no")
DEFAULT_SPACE = os.getenv("CONF_DEFAULT_SPACE", "").strip() or None


USE_HTML_FALLBACK = (
    (os.environ.get("ENABLE_SITE_SEARCH") or "").lower() in ("1","true","yes") or
    (os.environ.get("SITE_SEARCH_FALLBACK") or "").lower() in ("1","true","yes") or
    (os.environ.get("USE_HTML_SEARCH") or "").lower() in ("1","true","yes")
)

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
        out.append(_KO_POSTFIX.sub("", t))
    return [t for t in out if t]

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
    if not space and DEFAULT_SPACE:
        space = DEFAULT_SPACE  # conf_all 금지, 스페이스 한정
    # 목적지(os_destination)로 로그인 쿠키를 얻기 위해 한 번 더 로그인
    search_path = "/dosearchsite.action"
    params = {"queryString": text, "contentType": "page"}
    if space:
        params["where"] = "conf_space"
        params["spaceKey"] = space
        os_dest = f"/dosearchsite.action?queryString={quote_plus(text)}&contentType=page&where=conf_space&spaceKey={quote_plus(space)}"
    else:
        params["where"] = "conf_all"
        os_dest = f"/dosearchsite.action?queryString={quote_plus(text)}&contentType=page&where=conf_all"

    # 목적지 포함 로그인
    form = {
        "os_username": USER,
        "os_password": PASSWORD,
        "os_destination": f"{search_path}?queryString={quote_plus(text)}&contentType=page&" + \
                          ("where=conf_space&spaceKey="+quote_plus(space) if space else "where=conf_all")
    }
    sess.post(f"{BASE_URL}/dologin.action",
              data={"os_username": USER, "os_password": PASSWORD, "os_destination": os_dest},
              allow_redirects=True, headers={"X-Atlassian-Token": "no-check"})

    r = sess.get(f"{BASE_URL}/dosearchsite.action", params=params,
                 headers=_browser_headers(), timeout=30, allow_redirects=True)
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
    query = (payload or {}).get("query", "")
    limit = int((payload or {}).get("limit", 5) or 5)
    space = (payload or {}).get("space") or DEFAULT_SPACE

    text = _to_cql_text(query)
    if not text:
        return {"items": []}

    # --- 멀티 스페이스 파싱 ---
    spaces = []
    if space:
        spaces = [s.strip() for s in re.split(r"[,\s]+", str(space)) if s.strip()]

    # --- CQL 구성 ---
    parts = ['type=page', f'(title ~ "{text}" OR text ~ "{text}")']
    if spaces:
        if len(spaces) == 1:
            parts.append(f'space="{spaces[0]}"')
        else:
            joined = ", ".join(f'"{s}"' for s in spaces)
            parts.append(f"space in ({joined})")
    cql = " AND ".join(parts)

    params = {
        "cql": cql,
        "limit": max(1, min(limit, 50)),
        "expand": "space",
    }

    s = get_session_for_rest()
    r = s.get(SEARCH_API, params=params, timeout=30)

    if r.status_code in (401, 403):
        s = ensure_cookie_session()
        r = s.get(SEARCH_API, params=params, timeout=30)

    # JSON 실패/차단 시 폴백은 env가 true일 때만
    if r.status_code in (401, 403, 302) or "application/json" not in (r.headers.get("content-type","").lower()):
        if not USE_HTML_FALLBACK:
            return {"items": []}
        # HTML 폴백(멀티 스페이스 지원)
        items_all = []
        targets = spaces or [None]  # space 미지정이면 conf_all(권장X)이지만 기존 동작 유지
        for sp in targets:
            x = _html_search_fallback(s, text, sp, limit).get("items", [])
            items_all.extend(x)
            if len(items_all) >= limit:
                break
        # 중복 제거
        uniq, seen = [], set()
        for it in items_all:
            pid = it.get("page_id")
            if pid and pid not in seen:
                seen.add(pid); uniq.append(it)
        return {"items": uniq[:limit]}

    if r.status_code == 400:
        return {"items": []}
    r.raise_for_status()

    js = r.json() or {}
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
        items.append({
            "page_id": pid,
            "title": title,
            "url": page_view_url(pid),
            "excerpt": excerpt
        })
    # --- 0건이면 보강 재시도 ---
    if not items:
        # 공통 base
        if spaces:
            if len(spaces) == 1:
                base_space = f'space="{spaces[0]}"'
            else:
                joined = ", ".join(f'"{s}"' for s in spaces)
                base_space = f"space in ({joined})"
        else:
            base_space = ""

        base = "type=page" + (f" AND {base_space}" if base_space else "")
        toks = _norm_ko_tokens(text)[:4]
        guess = _guess_title(text)

        attempts = []
        if guess:
            attempts.append(f'{base} AND title ~ "{guess}"')
        if toks:
            # must 1~2개 (영문/숫자 또는 도메인 키워드 우선)
            must = []
            for tkn in toks:
                if tkn.isascii() or tkn in {"프로젝트","계획","개요","요구사항","보고서"}:
                    must.append(tkn)
                if len(must) >= 2:
                    break
            if not must:
                must = toks[:1]
            attempts.append(base + " AND " + " AND ".join([f'text ~ "{t}"' for t in must]))
            attempts.append(base + " AND (" + " OR ".join([f'title ~ "{t}"' for t in toks]) + ")")

        for cql2 in attempts:
            r2 = s.get(SEARCH_API,
                       params={"cql": cql2, "limit": max(1, min(limit, 50)), "expand": "space"},
                       timeout=30)
            if r2.status_code in (401, 403):
                s = ensure_cookie_session()
                r2 = s.get(SEARCH_API,
                           params={"cql": cql2, "limit": max(1, min(limit, 50)), "expand": "space"},
                           timeout=30)
            if r2.status_code == 200 and "application/json" in (r2.headers.get("content-type","").lower()):
                js2 = r2.json() or {}
                for rr in (js2.get("results") or []):
                    content = (rr.get("content") or {})
                    if content.get("type") != "page":
                        continue
                    pid = str(content.get("id") or "")
                    if not pid:
                        continue
                    title = content.get("title") or f"Page {pid}"
                    excerpt = _html_to_text(rr.get("excerpt") or "")[:300]
                    items.append({"page_id": pid, "title": title, "url": page_view_url(pid), "excerpt": excerpt})
                if items:
                    break
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
    js = r.json() or {}
    title = js.get("title") or f"Page {page_id}"
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