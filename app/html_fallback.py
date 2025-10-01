# html_fallback.py
import re, asyncio, httpx
from bs4 import BeautifulSoup

LOGIN_FORM = "/dologin.action"
SEARCH_HTML_CANDIDATES = [
    "/dosearchsite.action",
    "/searchsite.action",
]
VIEW_PAGE = "/pages/viewpage.action"

_NOISE_PAT = re.compile(r"(WRM\.|window\.)")
_LOGIN_PAT = re.compile(r"(Confluence에\s*로그인|name=[\"']os_username[\"'])", re.I)

class SessionClient:
    def __init__(self, base, user, password, timeout=20):
        self.base = base.rstrip("/")
        self.user = user
        self.password = password
        self.timeout = timeout
        self.client = httpx.AsyncClient(base_url=self.base, follow_redirects=True, timeout=timeout)

    async def login(self):
        # 이미 로그인되어 있으면 user/current가 200/JSON이 아닐 수 있으므로 그냥 강제 로그인 시도
        await self.client.post(LOGIN_FORM, data={
            "os_username": self.user,
            "os_password": self.password,
            "login": "Log In",
        })

    async def get(self, path, **kw):
        return await self.client.get(path, headers={"Accept":"text/html,application/xhtml+xml"}, **kw)

    async def close(self):
        await self.client.aclose()

def _clean_text(html: str) -> str:
    soup = BeautifulSoup(html, "lxml")
    # Confluence 6.x: 본문 후보
    main = (soup.select_one("#main-content") or
            soup.select_one("#content") or
            soup.select_one("div#confluence-content") or
            soup.select_one("div#content-body"))
    if not main:
        main = soup
    # 스크립트/스타일 제거
    for tag in main(["script","style","noscript"]):
        tag.decompose()
    txt = main.get_text("\n", strip=True)
    # 로그인/노이즈 필터
    if _LOGIN_PAT.search(txt):
        return ""
    lines = [L for L in (txt or "").splitlines() if not _NOISE_PAT.search(L)]
    return "\n".join(lines).strip()

async def search_html(base, user, password, query: str, limit: int = 5):
    cli = SessionClient(base, user, password)
    try:
        await cli.login()
        results = []
        # 여러 HTML 검색 엔드포인트 중 먼저 되는 것 사용
        for path in SEARCH_HTML_CANDIDATES:
            r = await cli.get(path, params={"queryString": query})
            if r.status_code != 200 or "text/html" not in r.headers.get("content-type",""):
                continue
            soup = BeautifulSoup(r.text, "lxml")
            # 결과 카드(Confluence 6.x DOM)
            cards = soup.select("div.search-results li.search-result")
            if not cards:
                # 다른 테마일 가능성: a.search-result-link 존재 여부로 보조
                cards = soup.select("a.search-result-link")
            for li in cards:
                a = li.select_one("a.search-result-link") if hasattr(li,"select_one") else None
                if a is None and hasattr(li, "get"):
                    a = li  # a.tag 자체가 후보인 경우
                title = (a.get_text(strip=True) if a else "").strip()
                href  = (a["href"] if a and a.has_attr("href") else "").strip()
                if not href:
                    continue
                # 절대 URL 보정
                if href.startswith("/"):
                    url = base.rstrip("/") + href
                elif href.startswith("http"):
                    url = href
                else:
                    url = base.rstrip("/") + "/" + href

                # 페이지 본문 가져오기
                body = ""
                # pageId 추출되면 viewpage로 재요청(광고/사이드 제거용)
                m = re.search(r"[?&]pageId=(\d+)", url)
                if m:
                    page_url = f"{VIEW_PAGE}?pageId={m.group(1)}"
                    rp = await cli.get(page_url)
                    if rp.status_code == 200:
                        body = _clean_text(rp.text)
                if not body:
                    rp = await cli.get(url)
                    if rp.status_code == 200:
                        body = _clean_text(rp.text)

                if not body:
                    continue
                results.append({
                    "id": m.group(1) if m else "",
                    "space": "",
                    "version": 0,
                    "title": title,
                    "url": url,
                    "body": body
                })
                if len(results) >= limit:
                    break
            if results:
                return results
        return []
    finally:
        await cli.close()
