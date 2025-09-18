import os
import re
import json
from typing import List, Optional, Dict, Any

import httpx
from bs4 import BeautifulSoup
from dotenv import load_dotenv

# FastMCP: 스트리머블 HTTP로 /mcp 엔드포인트 제공
from fastmcp import FastMCP

load_dotenv()

CONF_BASE = (os.getenv("CONFLUENCE_BASE_URL") or "").rstrip("/")
CONF_USER = os.getenv("CONFLUENCE_USER") or ""
CONF_PASS = os.getenv("CONFLUENCE_PASSWORD") or ""
VERIFY_SSL = (os.getenv("VERIFY_SSL", "true").lower() != "false")

if not (CONF_BASE and CONF_USER and CONF_PASS):
    raise SystemExit("Missing env: CONFLUENCE_BASE_URL / CONFLUENCE_USER / CONFLUENCE_PASSWORD")

# MCP 서버 인스턴스
app = FastMCP("Confluence MCP", transport="streamable-http")

# httpx 클라이언트 (커넥션 풀)
_client: httpx.AsyncClient | None = None

async def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(
            base_url=CONF_BASE,
            auth=(CONF_USER, CONF_PASS),
            timeout=httpx.Timeout(20.0, connect=10.0),
            verify=VERIFY_SSL,
        )
    return _client

def _page_url(page_id: str) -> str:
    # Server/DC 표준 보기 URL
    return f"{CONF_BASE}/pages/viewpage.action?pageId={page_id}"

def _html_to_text(html: str) -> str:
    if not html:
        return ""
    soup = BeautifulSoup(html, "html.parser")
    # 코드/표 등은 텍스트로 풀어줌
    text = soup.get_text(separator="\n", strip=True)
    # 공백 정리
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()

@app.tool()
async def confluence_search(
    query: str,
    space: Optional[str] = None,
    limit: int = 10
) -> List[Dict[str, Any]]:
    """
    Confluence CQL 검색.
    - query: CQL 또는 키워드 (키워드만 주면 title~ 혹은 text~로 매핑 시도)
    - space: 특정 스페이스 키 (예: 'ENG')
    - limit: 반환 개수
    """
    client = await get_client()

    # 키워드만 들어온 경우 간단한 CQL로 보정
    # (필요하면 여기서 title ~ "foo" OR text ~ "foo" 등으로 조합)
    cql = query
    if " " not in query and ":" not in query:
        cql = f'text ~ "{query}"'

    if space:
        cql = f'space = "{space}" AND ({cql})'

    params = {"cql": cql, "limit": str(limit)}
    r = await client.get("/rest/api/search", params=params)
    r.raise_for_status()
    data = r.json()

    out: List[Dict[str, Any]] = []
    for it in data.get("results", []):
        content = it.get("content") or {}
        cid = str(content.get("id") or it.get("id") or "")
        title = content.get("title") or it.get("title") or ""
        excerpt = it.get("excerpt") or ""
        out.append({
            "id": cid,
            "title": title,
            "url": _page_url(cid) if cid else None,
            "excerpt": excerpt
        })
    return out

@app.tool()
async def confluence_get_page(
    page_id: str,
    html: bool = False
) -> Dict[str, Any]:
    """
    페이지 ID로 본문 가져오기.
    - page_id: Confluence content ID
    - html: True면 storage HTML 포함
    """
    client = await get_client()
    r = await client.get(
        f"/rest/api/content/{page_id}",
        params={"expand": "body.storage,version,space"}
    )
    r.raise_for_status()
    d = r.json()
    body_html = (d.get("body", {}).get("storage", {}).get("value") or "")
    payload = {
        "id": str(d.get("id")),
        "title": d.get("title"),
        "url": _page_url(str(d.get("id"))),
        "space": (d.get("space") or {}).get("key"),
        "version": (d.get("version") or {}).get("number"),
        "body_text": _html_to_text(body_html),
    }
    if html:
        payload["body_html"] = body_html
    return payload

@app.tool()
async def confluence_get_by_url(
    url: str,
    html: bool = False
) -> Dict[str, Any]:
    """
    보기 URL(viewpage.action?pageId=...)에서 pageId를 추출해 get_page 수행.
    """
    m = re.search(r"[?&]pageId=(\d+)", url)
    if not m:
        raise ValueError("URL에서 pageId를 찾을 수 없습니다.")
    return await confluence_get_page(m.group(1), html=html)

@app.healthz()
async def healthz() -> Dict[str, Any]:
    client = await get_client()
    try:
        r = await client.get("/rest/api/space?limit=1")
        ok = r.status_code < 500
        return {"ok": ok}
    except Exception as e:
        return {"ok": False, "error": str(e)}

if __name__ == "__main__":
    # streamable-http → /mcp 엔드포인트 노출
    app.run(host="0.0.0.0", port=9000)
