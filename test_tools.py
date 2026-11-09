"""
Unit and localhost integration tests for the tools.py security-testing module.

Unit tests mock HTTP calls. Integration tests start a local HTTP server and use
the real HTTP request path; they never connect to external systems.
Run with:
    python -m unittest -v test_tools
"""

import base64
import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def make_mock_response(
    status_code: int,
    headers: dict,
    text: str,
    cookies: dict | None = None,
    elapsed: float = 0.1,
    url: str = "https://example.com/",
    history: list | None = None,
) -> MagicMock:
    """Return a MagicMock that mimics a requests.Response object."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers
    resp.text = text
    resp.content = text.encode("utf-8")
    resp.elapsed = MagicMock()
    resp.elapsed.total_seconds.return_value = elapsed
    resp.url = url
    resp.history = history or []

    # Cookies mock
    cookie_items = list((cookies or {}).items())
    resp.cookies = MagicMock()
    resp.cookies.items.return_value = cookie_items
    resp.cookies.get_dict.return_value = dict(cookies or {})

    return resp


# ---------------------------------------------------------------------------
# Base target JSON helpers
# ---------------------------------------------------------------------------

def _target(url: str = "https://example.com", **kwargs) -> str:
    data = {"target": url}
    data.update(kwargs)
    return json.dumps(data)


class _LocalIntegrationHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()

    def do_GET(self):
        body = b"Local integration response"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class TestLocalHttpIntegration(unittest.TestCase):
    """Exercise the real HTTP stack against an isolated loopback server."""

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _LocalIntegrationHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.target = f"http://127.0.0.1:{cls.server.server_port}/"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server_thread.join()
        cls.server.server_close()

    def _call_tool(self, function, **params):
        params.setdefault("target", self.target)
        params.setdefault("allowed_hosts", ["127.0.0.1"])
        return json.loads(function(json.dumps(params)))

    def test_validate_target_uses_real_http_request(self):
        import tools

        result = self._call_tool(tools.validate_target)

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["evidence"][0]["status_code"], 200)

    def test_analyze_response_reads_local_server_body(self):
        import tools

        result = self._call_tool(tools.analyze_http_response)

        self.assertEqual(result["status"], "success")
        self.assertIn("Local integration response", result["evidence"][0]["body_preview"])

    def test_allowlist_blocks_non_loopback_host(self):
        import tools

        result = self._call_tool(tools.analyze_http_response, allowed_hosts=["localhost"])

        self.assertEqual(result["status"], "skipped")


# ===========================================================================
# 1. validate_target
# ===========================================================================

class TestValidateTarget(unittest.TestCase):
    """Tests for tools.validate_target()"""

    def _call(self, payload: str) -> dict:
        import tools
        result = tools.validate_target(payload)
        return json.loads(result)

    @patch("tools._make_request")
    def test_valid_https_target(self, mock_req):
        """HEAD 200 on a valid https:// URL → status=success."""
        mock_req.return_value = make_mock_response(200, {}, "")
        result = self._call(_target("https://example.com"))
        self.assertNotEqual(result["status"], "error")
        self.assertEqual(result["status"], "success")

    def test_invalid_scheme(self):
        """ftp:// URL → status=error, no network call made."""
        with patch("tools._make_request") as mock_req:
            result = self._call(_target("ftp://example.com"))
            mock_req.assert_not_called()
            self.assertEqual(result["status"], "error")

    @patch("tools._make_request")
    def test_out_of_scope_host(self, mock_req):
        """Host not in allowed_hosts → status=skipped."""
        mock_req.return_value = make_mock_response(200, {}, "")
        payload = json.dumps({"target": "https://evil.com", "allowed_hosts": ["example.com"]})
        result = self._call(payload)
        self.assertEqual(result["status"], "skipped")

    @patch("tools._make_request")
    def test_connection_error(self, mock_req):
        """_make_request returns None (connection failure) → status=error."""
        mock_req.return_value = None
        result = self._call(_target("https://example.com"))
        self.assertEqual(result["status"], "error")

    def test_invalid_json_input(self):
        """Passing raw non-JSON string → status=error, no exception propagated."""
        import tools
        output = tools.validate_target("not json")
        result = json.loads(output)          # must still be valid JSON
        self.assertEqual(result["status"], "error")


# ===========================================================================
# 2. discover_endpoints
# ===========================================================================

class TestDiscoverEndpoints(unittest.TestCase):
    """Tests for tools.discover_endpoints()"""

    def _call(self, payload: str) -> dict:
        import tools
        result = tools.discover_endpoints(payload)
        return json.loads(result)

    @patch("tools._make_request")
    def test_discovers_swagger(self, mock_req):
        """/swagger.json returns 200 with JSON content → evidence contains swagger endpoint."""
        swagger_body = json.dumps({"openapi": "3.0.0", "info": {"title": "Test API"}})

        def side_effect(method, url, **kwargs):
            if "swagger" in url:
                return make_mock_response(200, {"Content-Type": "application/json"}, swagger_body, url=url)
            return make_mock_response(404, {}, "", url=url)

        mock_req.side_effect = side_effect
        result = self._call(_target("https://example.com"))
        self.assertNotEqual(result["status"], "error")
        evidence = result.get("evidence", [])
        swagger_found = any("swagger" in str(e).lower() for e in evidence)
        self.assertTrue(swagger_found, "Expected swagger endpoint in evidence")

    @patch("tools._make_request")
    def test_404_paths_excluded(self, mock_req):
        """All paths return 404 → evidence is empty list (no discovered endpoints)."""
        mock_req.return_value = make_mock_response(404, {}, "Not Found")
        result = self._call(_target("https://example.com"))
        evidence = result.get("evidence", [])
        self.assertEqual(len(evidence), 0)

    @patch("tools._make_request")
    def test_admin_path_found(self, mock_req):
        """/admin returns 200 → risk_indicator should be 'high'."""
        def side_effect(method, url, **kwargs):
            if "admin" in url:
                return make_mock_response(200, {}, "<html>Admin Panel</html>", url=url)
            return make_mock_response(404, {}, "", url=url)

        mock_req.side_effect = side_effect
        result = self._call(_target("https://example.com"))
        self.assertEqual(result["risk_indicator"], "high")

    @patch("tools._make_request")
    def test_robots_txt_found(self, mock_req):
        """/robots.txt returns 200 → endpoint in evidence."""
        def side_effect(method, url, **kwargs):
            if "robots.txt" in url:
                return make_mock_response(200, {"Content-Type": "text/plain"}, "User-agent: *\nDisallow: /admin", url=url)
            return make_mock_response(404, {}, "", url=url)

        mock_req.side_effect = side_effect
        result = self._call(_target("https://example.com"))
        evidence = result.get("evidence", [])
        robots_found = any("robots" in str(e).lower() for e in evidence)
        self.assertTrue(robots_found, "Expected robots.txt in evidence")


# ===========================================================================
# 3. analyze_http_response
# ===========================================================================

class TestAnalyzeHttpResponse(unittest.TestCase):
    """Tests for tools.analyze_http_response()"""

    def _call(self, payload: str) -> dict:
        import tools
        result = tools.analyze_http_response(payload)
        return json.loads(result)

    @patch("tools._make_request")
    def test_basic_200_response(self, mock_req):
        """Normal 200 response → status=success, finding mentions status code."""
        mock_req.return_value = make_mock_response(200, {"Content-Type": "text/html"}, "<html>OK</html>")
        result = self._call(_target("https://example.com"))
        self.assertEqual(result["status"], "success")
        self.assertIn("200", str(result.get("finding", "")))

    @patch("tools._make_request")
    def test_server_header_exposed(self, mock_req):
        """Server: Apache/2.4.1 header → evidence mentions server version."""
        mock_req.return_value = make_mock_response(
            200,
            {"Server": "Apache/2.4.1", "Content-Type": "text/html"},
            "<html>OK</html>",
        )
        result = self._call(_target("https://example.com"))
        evidence = result.get("evidence", [])
        server_found = any("Apache" in str(e) or "server" in str(e).lower() for e in evidence)
        self.assertTrue(server_found, "Expected server version disclosure in evidence")

    @patch("tools._make_request")
    def test_stack_trace_in_body(self, mock_req):
        """Body contains Python traceback → risk_indicator=high."""
        body = "Internal Error\nTraceback (most recent call last):\n  File 'app.py', line 42\nKeyError: 'id'"
        mock_req.return_value = make_mock_response(500, {"Content-Type": "text/html"}, body)
        result = self._call(_target("https://example.com"))
        self.assertEqual(result["risk_indicator"], "high")

    @patch("tools._make_request")
    def test_unsupported_method(self, mock_req):
        """method='INVALID' → status=error."""
        mock_req.return_value = make_mock_response(200, {}, "")
        payload = json.dumps({"target": "https://example.com", "method": "INVALID"})
        result = self._call(payload)
        self.assertEqual(result["status"], "error")


# ===========================================================================
# 4. check_security_headers
# ===========================================================================

class TestCheckSecurityHeaders(unittest.TestCase):
    """Tests for tools.check_security_headers()"""

    def _call(self, payload: str) -> dict:
        import tools
        result = tools.check_security_headers(payload)
        return json.loads(result)

    @patch("tools._make_request")
    def test_all_headers_present(self, mock_req):
        """All recommended security headers present → risk_indicator=informational."""
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        mock_req.return_value = make_mock_response(200, headers, "")
        result = self._call(_target("https://example.com"))
        self.assertEqual(result["risk_indicator"], "informational")

    @patch("tools._make_request")
    def test_missing_hsts(self, mock_req):
        """No Strict-Transport-Security header → risk_indicator=high."""
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
        }
        mock_req.return_value = make_mock_response(200, headers, "")
        result = self._call(_target("https://example.com"))
        self.assertEqual(result["risk_indicator"], "high")

    @patch("tools._make_request")
    def test_missing_csp(self, mock_req):
        """No Content-Security-Policy → risk_indicator=high."""
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
        }
        mock_req.return_value = make_mock_response(200, headers, "")
        result = self._call(_target("https://example.com"))
        self.assertEqual(result["risk_indicator"], "high")

    @patch("tools._make_request")
    def test_xcto_misconfigured(self, mock_req):
        """X-Content-Type-Options: 'sniff' → flagged as misconfigured."""
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "sniff",   # wrong value
        }
        mock_req.return_value = make_mock_response(200, headers, "")
        result = self._call(_target("https://example.com"))
        evidence = result.get("evidence", [])
        xcto_flagged = any("x-content-type" in str(e).lower() or "xcto" in str(e).lower() or "sniff" in str(e).lower() for e in evidence)
        self.assertTrue(xcto_flagged, "Expected X-Content-Type-Options misconfiguration in evidence")

    @patch("tools._make_request")
    def test_server_header_present(self, mock_req):
        """Server header in response → flagged as information disclosure."""
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "Server": "nginx/1.18.0",
        }
        mock_req.return_value = make_mock_response(200, headers, "")
        result = self._call(_target("https://example.com"))
        evidence = result.get("evidence", [])
        server_flagged = any("server" in str(e).lower() for e in evidence)
        self.assertTrue(server_flagged, "Expected Server header flagged in evidence")


# ===========================================================================
# 5. check_cors
# ===========================================================================

class TestCheckCors(unittest.TestCase):
    """Tests for tools.check_cors()"""

    def _call(self, payload: str) -> dict:
        import tools
        result = tools.check_cors(payload)
        return json.loads(result)

    @patch("tools._make_request")
    def test_wildcard_no_credentials(self, mock_req):
        """ACAO=* without ACAC → risk_indicator=low (not critical)."""
        mock_req.return_value = make_mock_response(
            200,
            {"Access-Control-Allow-Origin": "*"},
            "",
        )
        result = self._call(_target("https://example.com"))
        self.assertEqual(result["risk_indicator"], "low")

    @patch("tools._make_request")
    def test_wildcard_with_credentials(self, mock_req):
        """ACAO=* AND ACAC=true → risk_indicator=high."""
        mock_req.return_value = make_mock_response(
            200,
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
            "",
        )
        result = self._call(_target("https://example.com"))
        self.assertEqual(result["risk_indicator"], "high")

    @patch("tools._make_request")
    def test_reflected_origin_with_credentials(self, mock_req):
        """ACAO reflects evil.com and ACAC=true → risk_indicator=high."""
        def side_effect(method, url, **kwargs):
            # Simulate origin reflection
            origin = kwargs.get("headers", {}).get("Origin", "https://evil.com")
            return make_mock_response(
                200,
                {
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true",
                },
                "",
            )
        mock_req.side_effect = side_effect
        payload = json.dumps({"target": "https://example.com", "test_origin": "https://evil.com"})
        result = self._call(payload)
        self.assertEqual(result["risk_indicator"], "high")

    @patch("tools._make_request")
    def test_null_origin_allowed(self, mock_req):
        """ACAO=null → risk_indicator=medium."""
        mock_req.return_value = make_mock_response(
            200,
            {"Access-Control-Allow-Origin": "null"},
            "",
        )
        result = self._call(_target("https://example.com"))
        self.assertEqual(result["risk_indicator"], "medium")

    @patch("tools._make_request")
    def test_safe_cors(self, mock_req):
        """ACAO=https://example.com only → risk_indicator=informational."""
        mock_req.return_value = make_mock_response(
            200,
            {"Access-Control-Allow-Origin": "https://example.com"},
            "",
        )
        result = self._call(_target("https://example.com"))
        self.assertEqual(result["risk_indicator"], "informational")


# ===========================================================================
# 6. check_cookie_security
# ===========================================================================

class TestCheckCookieSecurity(unittest.TestCase):
    """Tests for tools.check_cookie_security()"""

    def _call(self, payload: str) -> dict:
        import tools
        result = tools.check_cookie_security(payload)
        return json.loads(result)

    @patch("tools._make_request")
    def test_secure_cookie(self, mock_req):
        """Cookie with Secure;HttpOnly;SameSite=Strict → no high risk findings."""
        headers = {
            "Set-Cookie": "session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/",
        }
        mock_req.return_value = make_mock_response(200, headers, "", cookies={"session": "abc123"})
        result = self._call(_target("https://example.com"))
        self.assertNotEqual(result["risk_indicator"], "high")

    @patch("tools._make_request")
    def test_missing_secure_flag(self, mock_req):
        """Session cookie without Secure flag on HTTPS URL → risk_indicator=high."""
        headers = {
            "Set-Cookie": "session=abc123; HttpOnly; SameSite=Strict; Path=/",
        }
        mock_req.return_value = make_mock_response(200, headers, "", cookies={"session": "abc123"})
        result = self._call(_target("https://example.com"))
        self.assertEqual(result["risk_indicator"], "high")

    @patch("tools._make_request")
    def test_missing_httponly(self, mock_req):
        """Session cookie without HttpOnly → medium risk evidence."""
        headers = {
            "Set-Cookie": "session=abc123; Secure; SameSite=Strict; Path=/",
        }
        mock_req.return_value = make_mock_response(200, headers, "", cookies={"session": "abc123"})
        result = self._call(_target("https://example.com"))
        evidence = result.get("evidence", [])
        httponly_flagged = any("httponly" in str(e).lower() for e in evidence)
        self.assertTrue(httponly_flagged, "Expected HttpOnly absence in evidence")

    @patch("tools._make_request")
    def test_samesite_none_no_secure(self, mock_req):
        """SameSite=None without Secure flag → flagged in evidence."""
        headers = {
            "Set-Cookie": "session=abc123; HttpOnly; SameSite=None; Path=/",
        }
        mock_req.return_value = make_mock_response(200, headers, "", cookies={"session": "abc123"})
        result = self._call(_target("https://example.com"))
        evidence = result.get("evidence", [])
        samesite_flagged = any("samesite" in str(e).lower() or "none" in str(e).lower() for e in evidence)
        self.assertTrue(samesite_flagged, "Expected SameSite=None without Secure to be flagged")


# ===========================================================================
# 7. check_sql_injection
# ===========================================================================

class TestCheckSqlInjection(unittest.TestCase):
    """Tests for tools.check_sql_injection()"""

    def _call(self, payload: str) -> dict:
        import tools
        result = tools.check_sql_injection(payload)
        return json.loads(result)

    @patch("tools._make_request")
    def test_error_message_in_response(self, mock_req):
        """One payload returns body with 'SQL syntax' → confidence=high."""
        call_count = [0]

        def side_effect(method, url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # baseline
                return make_mock_response(200, {}, "Normal response body", elapsed=0.1)
            # injection attempt — returns SQL error
            return make_mock_response(
                500,
                {"Content-Type": "text/html"},
                "You have an error in your SQL syntax near 'ORDER BY 1--'",
                elapsed=0.1,
            )

        mock_req.side_effect = side_effect
        payload = json.dumps({"target": "https://example.com/api/users", "param": "id"})
        result = self._call(payload)
        self.assertEqual(result["confidence"], "high")

    @patch("tools._make_request")
    def test_length_difference(self, mock_req):
        """Baseline=100 bytes, payload response=500 bytes → suspicious evidence."""
        baseline_body = "A" * 100
        large_body = "B" * 500
        call_count = [0]

        def side_effect(method, url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return make_mock_response(200, {}, baseline_body, elapsed=0.1)
            return make_mock_response(200, {}, large_body, elapsed=0.1)

        mock_req.side_effect = side_effect
        payload = json.dumps({"target": "https://example.com/api/users", "param": "id"})
        result = self._call(payload)
        evidence = result.get("evidence", [])
        length_flagged = any("length" in str(e).lower() or "size" in str(e).lower() or "differ" in str(e).lower() for e in evidence)
        self.assertTrue(length_flagged, "Expected length difference in evidence")

    @patch("tools._make_request")
    def test_time_based_detection(self, mock_req):
        """Sleep payload response time > 2.5s → time-based evidence."""
        call_count = [0]

        def side_effect(method, url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return make_mock_response(200, {}, "Normal", elapsed=0.1)
            return make_mock_response(200, {}, "Normal", elapsed=2.8)

        mock_req.side_effect = side_effect
        payload = json.dumps({"target": "https://example.com/api/users", "param": "id"})
        result = self._call(payload)
        evidence = result.get("evidence", [])
        time_flagged = any("time" in str(e).lower() or "sleep" in str(e).lower() or "delay" in str(e).lower() for e in evidence)
        self.assertTrue(time_flagged, "Expected time-based detection in evidence")

    @patch("tools._make_request")
    def test_no_injection_signs(self, mock_req):
        """All responses identical to baseline → risk_indicator=informational."""
        mock_req.return_value = make_mock_response(200, {}, "Normal response body", elapsed=0.1)
        payload = json.dumps({"target": "https://example.com/api/users", "param": "id"})
        result = self._call(payload)
        self.assertEqual(result["risk_indicator"], "informational")


# ===========================================================================
# 8. check_command_injection
# ===========================================================================

class TestCheckCommandInjection(unittest.TestCase):
    """Tests for tools.check_command_injection()"""

    def _call(self, payload: str) -> dict:
        import tools
        result = tools.check_command_injection(payload)
        return json.loads(result)

    @patch("tools._make_request")
    def test_probe_string_in_response(self, mock_req):
        """Response body contains 'RedTeamProbe2024' → confidence=high."""
        call_count = [0]

        def side_effect(method, url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return make_mock_response(200, {}, "Normal", elapsed=0.1)
            return make_mock_response(200, {}, "output: RedTeamProbe2024 uid=0(root)", elapsed=0.1)

        mock_req.side_effect = side_effect
        payload = json.dumps({"target": "https://example.com/api/ping", "param": "host"})
        result = self._call(payload)
        self.assertEqual(result["confidence"], "high")

    @patch("tools._make_request")
    def test_time_based_command(self, mock_req):
        """Sleep payload response time > 1.5s → time-based evidence."""
        call_count = [0]

        def side_effect(method, url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return make_mock_response(200, {}, "Normal", elapsed=0.1)
            return make_mock_response(200, {}, "Normal", elapsed=3.0)

        mock_req.side_effect = side_effect
        payload = json.dumps({"target": "https://example.com/api/ping", "param": "host"})
        result = self._call(payload)
        evidence = result.get("evidence", [])
        time_flagged = any("time" in str(e).lower() or "sleep" in str(e).lower() or "delay" in str(e).lower() for e in evidence)
        self.assertTrue(time_flagged, "Expected time-based command injection in evidence")

    @patch("tools._make_request")
    def test_no_injection_signs(self, mock_req):
        """No probe found, normal timing → risk_indicator=informational."""
        mock_req.return_value = make_mock_response(200, {}, "Normal", elapsed=0.1)
        payload = json.dumps({"target": "https://example.com/api/ping", "param": "host"})
        result = self._call(payload)
        self.assertEqual(result["risk_indicator"], "informational")


# ===========================================================================
# 9. check_idor
# ===========================================================================

class TestCheckIdor(unittest.TestCase):
    """Tests for tools.check_idor()"""

    def _call(self, payload: str) -> dict:
        import tools
        result = tools.check_idor(payload)
        return json.loads(result)

    @patch("tools._make_request")
    def test_b_accesses_a_resource(self, mock_req):
        """User B's token gets 200 on User A's resource with matching body → risk_indicator=high."""
        a_body = json.dumps({"id": 1, "name": "Alice", "email": "alice@example.com"})

        def side_effect(method, url, **kwargs):
            # Both A's request and B's unauthorised request return the same body
            return make_mock_response(200, {"Content-Type": "application/json"}, a_body)

        mock_req.side_effect = side_effect
        payload = json.dumps({
            "target": "https://example.com/api/users/1",
            "user_a_token": "token-alice",
            "user_b_token": "token-bob",
            "resource_id": "1",
        })
        result = self._call(payload)
        self.assertEqual(result["risk_indicator"], "high")

    @patch("tools._make_request")
    def test_unauthenticated_access(self, mock_req):
        """No token gets 200 on protected resource → risk_indicator=high."""
        body = json.dumps({"id": 1, "secret": "password123"})
        mock_req.return_value = make_mock_response(200, {"Content-Type": "application/json"}, body)
        payload = json.dumps({
            "target": "https://example.com/api/users/1",
            "user_a_token": "token-alice",
            "user_b_token": "",
            "resource_id": "1",
        })
        result = self._call(payload)
        self.assertEqual(result["risk_indicator"], "high")

    @patch("tools._make_request")
    def test_proper_403(self, mock_req):
        """User B's token gets 403 → risk_indicator=informational."""
        call_count = [0]

        def side_effect(method, url, **kwargs):
            call_count[0] += 1
            headers_sent = kwargs.get("headers", {})
            auth = headers_sent.get("Authorization", "")
            if "token-alice" in auth:
                return make_mock_response(200, {}, json.dumps({"id": 1, "name": "Alice"}))
            # Bob gets 403
            return make_mock_response(403, {}, "Forbidden")

        mock_req.side_effect = side_effect
        payload = json.dumps({
            "target": "https://example.com/api/users/1",
            "user_a_token": "token-alice",
            "user_b_token": "token-bob",
            "resource_id": "1",
        })
        result = self._call(payload)
        self.assertEqual(result["risk_indicator"], "informational")

    @patch("tools._make_request")
    def test_different_body_on_200(self, mock_req):
        """User B gets 200 but body differs from A's → confidence=medium (partial access)."""
        call_count = [0]

        def side_effect(method, url, **kwargs):
            call_count[0] += 1
            headers_sent = kwargs.get("headers", {})
            auth = headers_sent.get("Authorization", "")
            if "token-alice" in auth:
                return make_mock_response(200, {}, json.dumps({"id": 1, "name": "Alice", "ssn": "123-45-6789"}))
            # Bob gets a different body
            return make_mock_response(200, {}, json.dumps({"id": 1, "name": "Alice"}))

        mock_req.side_effect = side_effect
        payload = json.dumps({
            "target": "https://example.com/api/users/1",
            "user_a_token": "token-alice",
            "user_b_token": "token-bob",
            "resource_id": "1",
        })
        result = self._call(payload)
        self.assertEqual(result["confidence"], "medium")


# ===========================================================================
# 10. check_authentication
# ===========================================================================

def _make_alg_none_jwt() -> str:
    """Create a JWT with alg:none in header (not cryptographically valid)."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": "1234567890", "name": "Test User", "iat": 1516239022}).encode()
    ).rstrip(b"=").decode()
    # alg:none → empty signature
    return f"{header}.{payload}."


class TestCheckAuthentication(unittest.TestCase):
    """Tests for tools.check_authentication()"""

    def _call(self, payload: str) -> dict:
        import tools
        result = tools.check_authentication(payload)
        return json.loads(result)

    @patch("tools._make_request")
    def test_no_auth_returns_401(self, mock_req):
        """Unauthenticated request gets 401 → expected/safe behavior."""
        mock_req.return_value = make_mock_response(401, {"WWW-Authenticate": "Bearer"}, "Unauthorized")
        payload = json.dumps({
            "target": "https://example.com/api/protected",
            "valid_token": "valid-jwt-token",
        })
        result = self._call(payload)
        self.assertNotEqual(result["status"], "error")
        # 401 without token is expected; risk should not be high
        self.assertNotEqual(result["risk_indicator"], "high")

    @patch("tools._make_request")
    def test_invalid_token_returns_200(self, mock_req):
        """An invalid/garbage token is accepted with 200 → risk_indicator=high (broken auth)."""
        mock_req.return_value = make_mock_response(
            200, {"Content-Type": "application/json"}, json.dumps({"id": 1, "name": "Alice"})
        )
        payload = json.dumps({
            "target": "https://example.com/api/protected",
            "valid_token": "valid-jwt-token",
        })
        result = self._call(payload)
        self.assertEqual(result["risk_indicator"], "high")

    @patch("tools._make_request")
    def test_jwt_alg_none(self, mock_req):
        """valid_token is a JWT with alg:none → risk_indicator=high."""
        none_jwt = _make_alg_none_jwt()

        def side_effect(method, url, **kwargs):
            # Accept the alg:none JWT
            return make_mock_response(
                200, {"Content-Type": "application/json"}, json.dumps({"id": 1})
            )

        mock_req.side_effect = side_effect
        payload = json.dumps({
            "target": "https://example.com/api/protected",
            "valid_token": none_jwt,
        })
        result = self._call(payload)
        self.assertEqual(result["risk_indicator"], "high")

    @patch("tools._make_request")
    def test_valid_auth_works(self, mock_req):
        """Valid token accepted → status=success."""
        call_count = [0]

        def side_effect(method, url, **kwargs):
            call_count[0] += 1
            headers_sent = kwargs.get("headers", {})
            auth = headers_sent.get("Authorization", "")
            if "valid-jwt-token" in auth:
                return make_mock_response(
                    200, {"Content-Type": "application/json"}, json.dumps({"id": 1})
                )
            return make_mock_response(401, {}, "Unauthorized")

        mock_req.side_effect = side_effect
        payload = json.dumps({
            "target": "https://example.com/api/protected",
            "valid_token": "valid-jwt-token",
        })
        result = self._call(payload)
        self.assertEqual(result["status"], "success")


# ===========================================================================
# 11. check_sensitive_disclosure
# ===========================================================================

class TestCheckSensitiveDisclosure(unittest.TestCase):
    """Tests for tools.check_sensitive_disclosure()"""

    def _call(self, payload: str) -> dict:
        import tools
        result = tools.check_sensitive_disclosure(payload)
        return json.loads(result)

    @patch("tools._make_request")
    def test_aws_key_in_body(self, mock_req):
        """Body contains AWS key pattern → risk_indicator=high."""
        body = '{"config": {"aws_access_key": "AKIAIOSFODNN7EXAMPLE", "region": "us-east-1"}}'
        mock_req.return_value = make_mock_response(200, {"Content-Type": "application/json"}, body)
        result = self._call(_target("https://example.com/api/config"))
        self.assertEqual(result["risk_indicator"], "high")

    @patch("tools._make_request")
    def test_email_in_body(self, mock_req):
        """Body contains email address → evidence includes email finding."""
        body = '{"users": [{"email": "user@example.com", "id": 1}]}'
        mock_req.return_value = make_mock_response(200, {"Content-Type": "application/json"}, body)
        result = self._call(_target("https://example.com/api/users"))
        evidence = result.get("evidence", [])
        email_found = any("email" in str(e).lower() or "user@example.com" in str(e) for e in evidence)
        self.assertTrue(email_found, "Expected email disclosure in evidence")

    @patch("tools._make_request")
    def test_stack_trace_in_body(self, mock_req):
        """Body contains 'NullPointerException' → risk_indicator=medium."""
        body = "java.lang.NullPointerException\n\tat com.example.app.Service.process(Service.java:42)"
        mock_req.return_value = make_mock_response(500, {"Content-Type": "text/html"}, body)
        result = self._call(_target("https://example.com/api/process"))
        self.assertEqual(result["risk_indicator"], "medium")

    @patch("tools._make_request")
    def test_private_ip_in_body(self, mock_req):
        """Body contains private IP address → evidence includes IP finding."""
        body = '{"debug": {"internal_host": "192.168.1.100", "port": 8080}}'
        mock_req.return_value = make_mock_response(200, {"Content-Type": "application/json"}, body)
        result = self._call(_target("https://example.com/api/status"))
        evidence = result.get("evidence", [])
        ip_found = any("192.168" in str(e) or "ip" in str(e).lower() or "internal" in str(e).lower() for e in evidence)
        self.assertTrue(ip_found, "Expected private IP disclosure in evidence")

    @patch("tools._make_request")
    def test_clean_response(self, mock_req):
        """No sensitive data in response → risk_indicator=informational."""
        body = '{"status": "ok", "version": "1.0.0"}'
        mock_req.return_value = make_mock_response(200, {"Content-Type": "application/json"}, body)
        result = self._call(_target("https://example.com/api/health"))
        self.assertEqual(result["risk_indicator"], "informational")


# ===========================================================================
# Schema contract — verify every function returns expected keys
# ===========================================================================

REQUIRED_KEYS = {
    "tool", "status", "target", "finding",
    "evidence", "risk_indicator", "confidence",
    "recommendation", "next_step",
}


class TestResultSchema(unittest.TestCase):
    """Every public function must return a JSON object with the required keys."""

    def _assert_schema(self, json_str: str, func_name: str):
        result = json.loads(json_str)
        for key in REQUIRED_KEYS:
            self.assertIn(key, result, f"{func_name} result missing key: '{key}'")

    @patch("tools._make_request")
    def test_validate_target_schema(self, mock_req):
        import tools
        mock_req.return_value = make_mock_response(200, {}, "")
        self._assert_schema(tools.validate_target(_target()), "validate_target")

    @patch("tools._make_request")
    def test_discover_endpoints_schema(self, mock_req):
        import tools
        mock_req.return_value = make_mock_response(404, {}, "")
        self._assert_schema(tools.discover_endpoints(_target()), "discover_endpoints")

    @patch("tools._make_request")
    def test_analyze_http_response_schema(self, mock_req):
        import tools
        mock_req.return_value = make_mock_response(200, {}, "OK")
        self._assert_schema(tools.analyze_http_response(_target()), "analyze_http_response")

    @patch("tools._make_request")
    def test_check_security_headers_schema(self, mock_req):
        import tools
        mock_req.return_value = make_mock_response(200, {}, "")
        self._assert_schema(tools.check_security_headers(_target()), "check_security_headers")

    @patch("tools._make_request")
    def test_check_cors_schema(self, mock_req):
        import tools
        mock_req.return_value = make_mock_response(200, {}, "")
        self._assert_schema(tools.check_cors(_target()), "check_cors")

    @patch("tools._make_request")
    def test_check_cookie_security_schema(self, mock_req):
        import tools
        mock_req.return_value = make_mock_response(200, {}, "")
        self._assert_schema(tools.check_cookie_security(_target()), "check_cookie_security")

    @patch("tools._make_request")
    def test_check_sql_injection_schema(self, mock_req):
        import tools
        mock_req.return_value = make_mock_response(200, {}, "Normal", elapsed=0.1)
        self._assert_schema(
            tools.check_sql_injection(json.dumps({"target": "https://example.com/api/users", "param": "id"})),
            "check_sql_injection",
        )

    @patch("tools._make_request")
    def test_check_command_injection_schema(self, mock_req):
        import tools
        mock_req.return_value = make_mock_response(200, {}, "Normal", elapsed=0.1)
        self._assert_schema(
            tools.check_command_injection(json.dumps({"target": "https://example.com/api/ping", "param": "host"})),
            "check_command_injection",
        )

    @patch("tools._make_request")
    def test_check_idor_schema(self, mock_req):
        import tools
        mock_req.return_value = make_mock_response(403, {}, "Forbidden")
        self._assert_schema(
            tools.check_idor(json.dumps({
                "target": "https://example.com/api/users/1",
                "user_a_token": "token-alice",
                "user_b_token": "token-bob",
                "resource_id": "1",
            })),
            "check_idor",
        )

    @patch("tools._make_request")
    def test_check_authentication_schema(self, mock_req):
        import tools
        mock_req.return_value = make_mock_response(401, {}, "Unauthorized")
        self._assert_schema(
            tools.check_authentication(json.dumps({
                "target": "https://example.com/api/protected",
                "valid_token": "some-token",
            })),
            "check_authentication",
        )

    @patch("tools._make_request")
    def test_check_sensitive_disclosure_schema(self, mock_req):
        import tools
        mock_req.return_value = make_mock_response(200, {}, '{"status":"ok"}')
        self._assert_schema(tools.check_sensitive_disclosure(_target()), "check_sensitive_disclosure")


# ===========================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
