from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mylilpwny.core.state import Target
from mylilpwny.modules.webnum import (
    WebEnumModule,
    WebFingerprint,
    _extract_title,
    _fingerprint_from_response,
    _run_ffuf,
    _run_gobuster_dir,
)


# --- WebFingerprint ---

def test_web_fingerprint_to_dict():
    fp = WebFingerprint(url="http://10.0.0.1", status=200, title="Home", technologies=["nginx"])
    d = fp.to_dict()
    assert d["url"] == "http://10.0.0.1"
    assert d["status"] == 200
    assert "nginx" in d["technologies"]
    assert d["directories"] == []


# --- title extractor ---

def test_extract_title_found():
    assert _extract_title("<html><head><title>My App</title></head></html>") == "My App"

def test_extract_title_case_insensitive():
    assert _extract_title("<TITLE>Test</TITLE>") == "Test"

def test_extract_title_missing():
    assert _extract_title("<html><body>no title</body></html>") is None

def test_extract_title_with_attributes():
    assert _extract_title('<title lang="en">Hello</title>') == "Hello"


# --- fingerprint from response ---

def _mock_response(headers: dict, html: str = "") -> httpx.Response:
    resp = MagicMock(spec=httpx.Response)
    resp.headers = httpx.Headers(headers)
    resp.text = html
    return resp


def test_fingerprint_server_header():
    resp = _mock_response({"server": "Apache/2.4.52 (Ubuntu)"})
    techs = _fingerprint_from_response(resp, "")
    assert "Apache/2.4.52 (Ubuntu)" in techs

def test_fingerprint_x_powered_by():
    resp = _mock_response({"x-powered-by": "PHP/8.1.2"})
    techs = _fingerprint_from_response(resp, "")
    assert "PHP/8.1.2" in techs

def test_fingerprint_cloudflare():
    resp = _mock_response({"cf-ray": "abc123-LIS"})
    techs = _fingerprint_from_response(resp, "")
    assert "Cloudflare" in techs

def test_fingerprint_wordpress_html():
    resp = _mock_response({})
    techs = _fingerprint_from_response(resp, '<link rel="stylesheet" href="/wp-content/themes/x/style.css">')
    assert "WordPress" in techs

def test_fingerprint_aspnet_html():
    resp = _mock_response({})
    techs = _fingerprint_from_response(resp, '<input type="hidden" name="__VIEWSTATE" value="abc"/>')
    assert "ASP.NET" in techs

def test_fingerprint_generator_meta():
    resp = _mock_response({})
    techs = _fingerprint_from_response(resp, '<meta name="generator" content="WordPress 6.3"/>')
    assert "WordPress 6.3" in techs

def test_fingerprint_no_headers():
    resp = _mock_response({})
    assert _fingerprint_from_response(resp, "") == []


# --- ffuf / gobuster ---

@pytest.mark.asyncio
async def test_ffuf_not_installed():
    with patch("shutil.which", return_value=None):
        result = await _run_ffuf("http://10.0.0.1", "/some/wordlist.txt", 30)
    assert result == []

@pytest.mark.asyncio
async def test_gobuster_dir_not_installed():
    with patch("shutil.which", return_value=None):
        result = await _run_gobuster_dir("http://10.0.0.1", "/some/wordlist.txt", 30)
    assert result == []


# --- WebEnumModule ---

@pytest.mark.asyncio
async def test_webnum_run_active_host():
    mod = WebEnumModule()
    target = Target(input="10.0.0.1", ip="10.0.0.1")

    mock_fp = WebFingerprint(
        url="http://10.0.0.1",
        status=200,
        title="Test",
        technologies=["nginx"],
    )

    with (
        patch("mylilpwny.modules.webnum._probe_url", new_callable=AsyncMock, return_value=mock_fp),
        patch("mylilpwny.modules.webnum._run_whatweb", new_callable=AsyncMock, return_value=["PHP/8.1"]),
    ):
        result = await mod.run(target, {"ports": [80]})

    assert result.status == "success"
    assert len(result.parsed_findings) == 1
    fp = result.parsed_findings[0]
    assert fp["title"] == "Test"
    assert "PHP/8.1" in fp["technologies"]


@pytest.mark.asyncio
async def test_webnum_run_no_active_hosts():
    mod = WebEnumModule()
    target = Target(input="10.0.0.1", ip="10.0.0.1")

    with patch("mylilpwny.modules.webnum._probe_url", new_callable=AsyncMock, return_value=None):
        result = await mod.run(target, {"ports": [80, 443]})

    assert result.status == "success"
    assert result.parsed_findings == []


@pytest.mark.asyncio
async def test_webnum_brute_force_skipped_by_default():
    mod = WebEnumModule()
    target = Target(input="10.0.0.1", ip="10.0.0.1")

    mock_fp = WebFingerprint(url="http://10.0.0.1", status=200)

    with (
        patch("mylilpwny.modules.webnum._probe_url", new_callable=AsyncMock, return_value=mock_fp),
        patch("mylilpwny.modules.webnum._run_whatweb", new_callable=AsyncMock, return_value=[]),
        patch("mylilpwny.modules.webnum._run_ffuf", new_callable=AsyncMock) as mock_ffuf,
    ):
        await mod.run(target, {"ports": [80]})
        mock_ffuf.assert_not_called()


@pytest.mark.asyncio
async def test_webnum_brute_force_enabled():
    mod = WebEnumModule()
    target = Target(input="10.0.0.1", ip="10.0.0.1")

    mock_fp = WebFingerprint(url="http://10.0.0.1", status=200)

    with (
        patch("mylilpwny.modules.webnum._probe_url", new_callable=AsyncMock, return_value=mock_fp),
        patch("mylilpwny.modules.webnum._run_whatweb", new_callable=AsyncMock, return_value=[]),
        patch("mylilpwny.modules.webnum._run_ffuf", new_callable=AsyncMock, return_value=["/admin", "/login"]),
        patch("os.path.exists", return_value=True),
    ):
        result = await mod.run(target, {
            "ports": [80],
            "brute_force": True,
            "wordlist": "/fake/wordlist.txt",
        })

    assert "/admin" in result.parsed_findings[0]["directories"]


def test_webnum_attributes():
    mod = WebEnumModule()
    assert mod.name == "webnum"
    assert mod.risk_level == "medium"
