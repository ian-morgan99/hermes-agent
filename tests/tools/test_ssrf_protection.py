"""Tests for SSRF protection in web_tools.py.

Coverage:
  _validate_url_not_ssrf() — private IPv4 ranges, IPv6 loopback, link-local
  metadata endpoint (169.254.x.x), non-http schemes, DNS failure blocks, public
  URLs pass through.
"""

import pytest
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Unit tests for _validate_url_not_ssrf
# ---------------------------------------------------------------------------

class TestValidateUrlNotSsrf:
    """Direct tests for the SSRF URL validator."""

    def _validate(self, url: str):
        from tools.web_tools import _validate_url_not_ssrf
        return _validate_url_not_ssrf(url)

    def _error_class(self):
        from tools.web_tools import _SsrfBlockedError
        return _SsrfBlockedError

    # -- private IPv4 ranges should be blocked --

    def test_loopback_127_blocked(self):
        with pytest.raises(ValueError, match="private/internal"):
            self._validate("http://127.0.0.1/")

    def test_loopback_127_alt_blocked(self):
        with pytest.raises(ValueError, match="private/internal"):
            self._validate("http://127.1.2.3/")

    def test_rfc1918_10_blocked(self):
        with pytest.raises(ValueError, match="private/internal"):
            self._validate("http://10.0.0.1/admin")

    def test_rfc1918_172_blocked(self):
        with pytest.raises(ValueError, match="private/internal"):
            self._validate("http://172.16.0.1/")

    def test_rfc1918_192_168_blocked(self):
        with pytest.raises(ValueError, match="private/internal"):
            self._validate("http://192.168.1.1/")

    def test_link_local_169_254_blocked(self):
        """AWS/GCP metadata service — must be blocked."""
        with pytest.raises(ValueError, match="private/internal"):
            self._validate("http://169.254.169.254/latest/meta-data/")

    def test_broadcast_blocked(self):
        with pytest.raises(ValueError, match="private/internal"):
            self._validate("http://255.255.255.255/")

    # -- IPv6 private ranges should be blocked --

    def test_ipv6_loopback_blocked(self):
        with pytest.raises(ValueError, match="private/internal"):
            self._validate("http://[::1]/")

    def test_ipv6_link_local_blocked(self):
        with pytest.raises(ValueError, match="private/internal"):
            self._validate("http://[fe80::1]/")

    # -- non-http schemes must be rejected --

    def test_file_scheme_rejected(self):
        with pytest.raises(ValueError, match="scheme"):
            self._validate("file:///etc/passwd")

    def test_ftp_scheme_rejected(self):
        with pytest.raises(ValueError, match="scheme"):
            self._validate("ftp://example.com/file.txt")

    def test_data_scheme_rejected(self):
        with pytest.raises(ValueError, match="scheme"):
            self._validate("data:text/html,<h1>hi</h1>")

    # -- DNS failure is treated as blocked (fail-secure) --

    def test_dns_resolution_failure_blocks_request(self):
        """If DNS resolution fails, the request must be blocked (fail-secure)."""
        import socket
        with patch("tools.web_tools._is_ssrf_blocked", return_value=True):
            with pytest.raises(ValueError, match="private/internal"):
                self._validate("https://nonexistent-host.internal/api")

    # -- public URLs should pass through --

    def test_public_https_allowed(self):
        """Public HTTPS URL should not raise."""
        # Patch _is_ssrf_blocked to avoid actual DNS resolution in unit test
        with patch("tools.web_tools._is_ssrf_blocked", return_value=False):
            self._validate("https://example.com/page")

    def test_public_http_allowed(self):
        with patch("tools.web_tools._is_ssrf_blocked", return_value=False):
            self._validate("http://example.com/page")

    # -- hostname-based SSRF via DNS --

    def test_hostname_resolving_to_private_blocked(self):
        """If a hostname resolves to a private IP, it must be blocked."""
        import socket
        # Simulate a hostname that resolves to 10.0.0.1 (private)
        with patch("tools.web_tools._is_ssrf_blocked", return_value=True):
            with pytest.raises(ValueError, match="private/internal"):
                self._validate("https://internal-service.corp/api")

    def test_hostname_resolving_to_public_allowed(self):
        with patch("tools.web_tools._is_ssrf_blocked", return_value=False):
            self._validate("https://api.example.com/v1/data")


class TestIsSsrfBlocked:
    """Unit tests for the _is_ssrf_blocked DNS-resolution helper."""

    def test_dns_failure_returns_true_fail_secure(self):
        """A DNS resolution failure must return True (block) for fail-secure behavior."""
        import socket
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN")):
            from tools.web_tools import _is_ssrf_blocked
            assert _is_ssrf_blocked("nonexistent.internal") is True

    def test_private_ip_returns_true(self):
        """A hostname resolving to a private IP must return True."""
        import socket
        # Fake DNS resolution to 10.0.0.1
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, None, None, None, ("10.0.0.1", 0))]):
            from tools.web_tools import _is_ssrf_blocked
            assert _is_ssrf_blocked("internal.corp") is True

    def test_public_ip_returns_false(self):
        """A hostname resolving to a public IP must return False."""
        import socket
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, None, None, None, ("93.184.216.34", 0))]):
            from tools.web_tools import _is_ssrf_blocked
            assert _is_ssrf_blocked("example.com") is False


# ---------------------------------------------------------------------------
# Integration-level tests for web_extract_tool SSRF guard
# ---------------------------------------------------------------------------

class TestWebExtractToolSsrfGuard:
    """web_extract_tool must reject private URLs without calling Firecrawl."""

    @pytest.fixture(autouse=True)
    def _reset_client(self):
        import tools.web_tools
        tools.web_tools._firecrawl_client = None
        yield
        tools.web_tools._firecrawl_client = None

    @pytest.mark.asyncio
    async def test_private_url_blocked_before_firecrawl(self):
        """Private URL must return an error without calling Firecrawl."""
        import json
        from unittest.mock import AsyncMock, MagicMock, patch

        mock_client = MagicMock()
        mock_client.scrape = MagicMock(return_value={})

        with patch("tools.web_tools._get_firecrawl_client", return_value=mock_client):
            from tools.web_tools import web_extract_tool
            result_str = await web_extract_tool(
                urls=["http://169.254.169.254/latest/meta-data/"],
                format="markdown",
                use_llm_processing=False,
            )

        result = json.loads(result_str)
        results = result.get("results", [])
        # The private URL should appear in the results but with an error
        assert len(results) == 1
        assert "error" in results[0]
        assert "private" in results[0]["error"].lower() or "internal" in results[0]["error"].lower()
        # Firecrawl should NOT have been called
        mock_client.scrape.assert_not_called()

    @pytest.mark.asyncio
    async def test_mixed_urls_only_public_fetched(self):
        """Private URLs are skipped; public URLs are still fetched."""
        import json
        from unittest.mock import MagicMock, patch, AsyncMock

        mock_scrape_result = MagicMock()
        mock_scrape_result.model_dump.return_value = {
            "markdown": "# Hello",
            "html": None,
            "metadata": {"title": "Hello", "sourceURL": "https://example.com/"},
        }
        mock_client = MagicMock()
        mock_client.scrape = MagicMock(return_value=mock_scrape_result)

        with patch("tools.web_tools._get_firecrawl_client", return_value=mock_client), \
             patch("tools.web_tools._is_ssrf_blocked", return_value=False):
            from tools.web_tools import web_extract_tool
            result_str = await web_extract_tool(
                urls=["http://10.0.0.1/admin", "https://example.com/"],
                format="markdown",
                use_llm_processing=False,
            )

        result = json.loads(result_str)
        pages = result.get("results", [])
        assert len(pages) == 2
        # Private URL has error
        private_page = next(p for p in pages if "10.0.0.1" in p.get("url", ""))
        assert "error" in private_page
        # Public URL was fetched (scrape called once)
        mock_client.scrape.assert_called_once()


# ---------------------------------------------------------------------------
# Integration-level tests for web_crawl_tool SSRF guard
# ---------------------------------------------------------------------------

class TestWebCrawlToolSsrfGuard:
    """web_crawl_tool must reject private URLs without calling Firecrawl."""

    @pytest.fixture(autouse=True)
    def _reset_client(self):
        import tools.web_tools
        tools.web_tools._firecrawl_client = None
        yield
        tools.web_tools._firecrawl_client = None

    @pytest.mark.asyncio
    async def test_private_url_crawl_blocked(self):
        """Crawling a private URL must return an error without calling Firecrawl."""
        import json
        from unittest.mock import MagicMock, patch

        mock_client = MagicMock()
        mock_client.crawl = MagicMock(return_value={})

        with patch("tools.web_tools._get_firecrawl_client", return_value=mock_client):
            from tools.web_tools import web_crawl_tool
            result_str = await web_crawl_tool(
                url="http://192.168.1.1/",
                use_llm_processing=False,
            )

        result = json.loads(result_str)
        assert "error" in result
        assert "private" in result["error"].lower() or "internal" in result["error"].lower()
        mock_client.crawl.assert_not_called()
