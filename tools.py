"""
tools.py — Web & API Security Testing Tools
AI Supported Autonomous Red Team System

This module acts as the execution and evidence collection layer for an AI-powered
autonomous red team agent. Every public function accepts a JSON string input and
returns a JSON string output following a strict result schema.

The AI agent is responsible for:
  - Deciding which tool to invoke
  - Interpreting JSON output
  - Selecting subsequent tests
  - Generating the final security report

This module is NEVER responsible for:
  - Making final vulnerability declarations
  - Generating security reports
  - Executing destructive operations

LEGAL NOTICE: Use only on systems for which explicit written authorization has been obtained.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] tools: %(message)s",
)
logger = logging.getLogger("redteam.tools")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class ToolConfig:
    """Module-level configuration for the security testing tools.

    Attributes:
        timeout: HTTP request timeout in seconds.
        rate_limit_rps: Maximum requests per second (per host).
        verify_tls: Whether to verify TLS certificates.
        allowed_hosts: Allowlisted hostnames (populated per test session).
        max_redirects: Maximum number of redirects to follow.
    """
    timeout: float = 10.0
    rate_limit_rps: float = 2.0
    verify_tls: bool = True
    allowed_hosts: set[str] = field(default_factory=set)
    max_redirects: int = 3


_CONFIG = ToolConfig()


def _build_session() -> requests.Session:
    """Create a shared requests.Session with retry and connection pooling."""
    session = requests.Session()
    retry = Retry(
        total=1,
        backoff_factor=0.3,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({
        "User-Agent": "RedTeam-Agent/1.0 (Authorized Security Testing)",
        "Accept": "*/*",
    })
    return session


_SESSION = _build_session()


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Thread-safe token-bucket rate limiter per host."""

    def __init__(self, rps: float) -> None:
        self._rps = rps
        self._locks: dict[str, threading.Lock] = {}
        self._last_call: dict[str, float] = {}
        self._global_lock = threading.Lock()

    def _get_host_lock(self, host: str) -> threading.Lock:
        with self._global_lock:
            if host not in self._locks:
                self._locks[host] = threading.Lock()
            return self._locks[host]

    def wait(self, host: str) -> None:
        """Block until the rate limit allows the next request to `host`."""
        lock = self._get_host_lock(host)
        with lock:
            now = time.monotonic()
            last = self._last_call.get(host, 0.0)
            interval = 1.0 / self._rps
            elapsed = now - last
            if elapsed < interval:
                time.sleep(interval - elapsed)
            self._last_call[host] = time.monotonic()


_RATE_LIMITER = _RateLimiter(rps=_CONFIG.rate_limit_rps)


# ---------------------------------------------------------------------------
# Private Helpers
# ---------------------------------------------------------------------------

_SENSITIVE_KEY_PATTERN = re.compile(
    r"^(password|passwd|secret|api[_-]?key|private[_-]?key|"
    r"authorization|cookie|credential|token|auth|bearer)$",
    re.IGNORECASE,
)

_PRIVATE_IP_PATTERNS = [
    re.compile(r"^10\.\d+\.\d+\.\d+$"),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$"),
    re.compile(r"^192\.168\.\d+\.\d+$"),
    re.compile(r"^127\.\d+\.\d+\.\d+$"),
    re.compile(r"^::1$"),
    re.compile(r"^fc[0-9a-f]{2}::", re.IGNORECASE),
]


def _is_private_ip(hostname: str) -> bool:
    """Return True if hostname is a private/loopback IP address."""
    return any(p.match(hostname) for p in _PRIVATE_IP_PATTERNS)


def _redact_sensitive(data: Any) -> Any:
    """Recursively redact sensitive key values in dicts and lists."""
    if isinstance(data, dict):
        return {
            k: "[REDACTED]" if _SENSITIVE_KEY_PATTERN.match(str(k)) else _redact_sensitive(v)
            for k, v in data.items()
        }
    if isinstance(data, list):
        return [_redact_sensitive(item) for item in data]
    return data


def _parse_input(raw: str) -> dict:
    """Parse a JSON string into a dictionary."""
    try:
        data = json.loads(raw)
    except Exception as exc:
        raise ValueError(f"Invalid JSON input: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("Input must be a JSON object (dict), not a list or scalar.")
    return data


def _extract_target_url(params: dict) -> str:
    """Extract target URL from common aliases (url, target, base_url, protected_url)."""
    return (
        params.get("url")
        or params.get("target")
        or params.get("base_url")
        or params.get("protected_url")
        or ""
    ).strip()


def _resolve_allowed_hosts(params: dict, target_url: str = "") -> set[str]:
    """Extract and normalise allowed_hosts.

    If allowed_hosts is explicitly provided in params, use that strictly.
    If omitted and target_url is provided, auto-permit target host for testing ease.
    """
    raw = params.get("allowed_hosts")
    if raw is not None:
        if isinstance(raw, str):
            raw = [raw]
        hosts = {str(h).strip().lower().lstrip("*.") for h in raw if h}
        _CONFIG.allowed_hosts.update(hosts)
        return hosts

    # If allowed_hosts not explicitly passed, permit the target's own host
    if target_url:
        try:
            h = urlparse(target_url).hostname
            if h:
                return {h.lower()}
        except Exception:
            pass

    return _CONFIG.allowed_hosts


def _validate_scope(url: str, allowed_hosts: set[str] | None = None) -> bool:
    """Check whether a URL is within authorized test scope."""
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
    except Exception:
        return False

    if not hostname:
        return False

    hosts = allowed_hosts if allowed_hosts is not None else _CONFIG.allowed_hosts
    if not hosts:
        # Default allow if no hosts configured
        return True

    if _is_private_ip(hostname) and hostname not in hosts:
        logger.warning("Scope violation: private IP %s not in allowlist", hostname)
        return False

    for allowed in hosts:
        allowed_clean = allowed.lstrip("*.").lower()
        if hostname == allowed_clean or hostname.endswith("." + allowed_clean):
            return True

    logger.warning("Scope violation: host %s not in allowlist %s", hostname, hosts)
    return False


def _build_result(
    *,
    tool: str,
    status: str,
    target: str,
    finding: str,
    evidence: list[Any],
    risk_indicator: str,
    confidence: str,
    recommendation: str,
    next_step: str,
) -> str:
    """Serialise a result dict to a standard JSON string."""
    result = {
        "tool": tool,
        "status": status,
        "target": target,
        "finding": finding,
        "evidence": _redact_sensitive(evidence),
        "risk_indicator": risk_indicator,
        "confidence": confidence,
        "recommendation": recommendation,
        "next_step": next_step,
    }
    return json.dumps(result, default=str)


def _error_result(tool: str, target: str, message: str) -> str:
    """Return a standard error result."""
    return _build_result(
        tool=tool,
        status="error",
        target=target,
        finding=f"Tool execution error: {message}",
        evidence=[{"error": message}],
        risk_indicator="unknown",
        confidence="low",
        recommendation="Investigate the error before continuing.",
        next_step="Retry with corrected input or skip this check.",
    )


def _skipped_result(tool: str, target: str, reason: str) -> str:
    """Return a standard skipped result when scope validation fails."""
    return _build_result(
        tool=tool,
        status="skipped",
        target=target,
        finding=f"Test skipped: {reason}",
        evidence=[{"reason": reason}],
        risk_indicator="unknown",
        confidence="low",
        recommendation="Ensure the target is in the authorized allowlist.",
        next_step="Update allowed_hosts to include the target, or use a different target.",
    )


def _make_request(
    method: str,
    url: str,
    **kwargs: Any,
) -> requests.Response | None:
    """Send an HTTP request within scope constraints.

    Accepts (method, url, **kwargs) to remain 100% compatible with test mocks.
    """
    allowed_hosts = kwargs.pop("allowed_hosts", None)
    if allowed_hosts is not None and not _validate_scope(url, allowed_hosts):
        logger.warning("Request blocked (out of scope): %s", url)
        return None

    parsed = urlparse(url)
    hostname = parsed.hostname or url
    _RATE_LIMITER.wait(hostname)

    kwargs.setdefault("timeout", _CONFIG.timeout)
    kwargs.setdefault("verify", _CONFIG.verify_tls)
    allow_redirects = kwargs.pop("allow_redirects", True)

    try:
        kwargs["allow_redirects"] = False
        response = _SESSION.request(method, url, **kwargs)
        if response is None:
            return None

        # Handle redirects manually to enforce scope
        if allow_redirects and getattr(response, "is_redirect", False):
            hops = 0
            while getattr(response, "is_redirect", False) and hops < _CONFIG.max_redirects:
                location = response.headers.get("Location", "")
                redirect_url = urljoin(url, location)
                if allowed_hosts is not None and not _validate_scope(redirect_url, allowed_hosts):
                    logger.warning("Redirect blocked (out of scope): %s", redirect_url)
                    break
                _RATE_LIMITER.wait(urlparse(redirect_url).hostname or redirect_url)
                response = _SESSION.request(method, redirect_url, **kwargs)
                hops += 1

        return response

    except requests.Timeout:
        logger.debug("Request timed out: %s %s", method, url)
        return None
    except requests.TooManyRedirects:
        logger.debug("Too many redirects: %s", url)
        return None
    except requests.ConnectionError:
        logger.debug("Connection error: %s %s", method, url)
        return None
    except requests.RequestException as exc:
        logger.debug("Request error: %s %s — %s", method, url, exc)
        return None
    except Exception as exc:
        logger.debug("Unexpected error in request: %s", exc)
        return None


def _get_elapsed_seconds(resp: Any, fallback: float) -> float:
    """Get elapsed response time from response object or fallback."""
    if resp is not None and hasattr(resp, "elapsed"):
        elapsed_obj = resp.elapsed
        if hasattr(elapsed_obj, "total_seconds"):
            try:
                return float(elapsed_obj.total_seconds())
            except Exception:
                pass
    return fallback


def _parse_headers(response: Any) -> dict[str, str]:
    """Return a lowercase-keyed header dict, redacting Set-Cookie values."""
    result = {}
    if response is None or not hasattr(response, "headers") or not response.headers:
        return result
    for name, value in response.headers.items():
        key = name.lower()
        if key in ("set-cookie", "cookie"):
            result[key] = "[REDACTED]"
        else:
            result[key] = str(value)
    return result


def _parse_set_cookie_header(raw: str) -> dict | None:
    """Parse a raw Set-Cookie header string into a structured dict."""
    if not raw:
        return None
    parts = [p.strip() for p in raw.split(";")]
    if not parts:
        return None

    name_value = parts[0]
    if "=" not in name_value:
        return None

    name, _, value = name_value.partition("=")
    attrs = {
        p.lower().split("=")[0].strip(): p.split("=")[1].strip() if "=" in p else True
        for p in parts[1:]
    }

    preview = value[:4] + "***" if len(value) > 4 else "***"
    return {
        "name": name.strip(),
        "value_preview": preview,
        "secure": "secure" in attrs,
        "httponly": "httponly" in attrs,
        "samesite": str(attrs.get("samesite", "")) if attrs.get("samesite") else "",
        "domain": str(attrs.get("domain", "")),
        "path": str(attrs.get("path", "/")),
    }


# ---------------------------------------------------------------------------
# Public Tool Functions
# ---------------------------------------------------------------------------

def validate_target(input_json: str) -> str:
    """Validate target URL, hostname, protocol, and scope."""
    tool_name = "validate_target"
    target = ""
    try:
        params = _parse_input(input_json)
        target = _extract_target_url(params)
        if not target:
            return _error_result(tool_name, target, "Missing required parameter: 'target' or 'url'")

        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https"):
            return _error_result(tool_name, target, f"Unsupported scheme '{parsed.scheme}'. Only http/https are allowed.")

        allowed_hosts = _resolve_allowed_hosts(params, target)
        if not _validate_scope(target, allowed_hosts):
            return _skipped_result(tool_name, target, f"Host '{parsed.hostname}' is not in allowed_hosts.")

        t_start = time.monotonic()
        response = _make_request("HEAD", target, allowed_hosts=allowed_hosts, allow_redirects=True)
        if response is None:
            response = _make_request("GET", target, allowed_hosts=allowed_hosts, allow_redirects=True)

        if response is None:
            return _error_result(tool_name, target, "Target is unreachable. Connection failed or timed out.")

        elapsed_ms = round(_get_elapsed_seconds(response, time.monotonic() - t_start) * 1000)
        tls_valid = target.startswith("https://")
        server_header = getattr(response, "headers", {}).get("Server", "not disclosed")
        redirect_count = len(getattr(response, "history", []))
        status_code = getattr(response, "status_code", 200)

        evidence = [{
            "type": "reachability",
            "status_code": status_code,
            "tls_used": tls_valid,
            "response_time_ms": elapsed_ms,
            "server_header": server_header,
            "redirect_count": redirect_count,
            "final_url": getattr(response, "url", target),
        }]

        finding = (
            f"Target reachable via {'HTTPS' if tls_valid else 'HTTP'}. "
            f"Status: {status_code}. Response time: {elapsed_ms}ms. "
            f"Server: {server_header}."
        )

        return _build_result(
            tool=tool_name,
            status="success",
            target=target,
            finding=finding,
            evidence=evidence,
            risk_indicator="informational",
            confidence="high",
            recommendation="Proceed with security assessment on this target.",
            next_step="Call discover_endpoints to map the attack surface.",
        )

    except ValueError as exc:
        return _error_result(tool_name, target, str(exc))
    except Exception as exc:
        logger.exception("Unexpected error in %s", tool_name)
        return _error_result(tool_name, target, f"Unexpected error: {exc}")


def discover_endpoints(input_json: str) -> str:
    """Discover accessible Web and API endpoints."""
    tool_name = "discover_endpoints"
    target = ""
    try:
        params = _parse_input(input_json)
        target = _extract_target_url(params)
        if not target:
            return _error_result(tool_name, target, "Missing required parameter: 'target' or 'base_url'")

        allowed_hosts = _resolve_allowed_hosts(params, target)
        if not _validate_scope(target, allowed_hosts):
            return _skipped_result(tool_name, target, "Target is out of authorized scope.")

        wordlist = params.get("wordlist")
        if not wordlist:
            wordlist = [
                "/swagger.json", "/openapi.json", "/api-docs", "/robots.txt",
                "/admin", "/login", "/health", "/api/v1",
            ]
        else:
            wordlist = [f"/{w.lstrip('/')}" for w in wordlist]
            for common in ["/swagger.json", "/robots.txt", "/admin"]:
                if common not in wordlist:
                    wordlist.append(common)

        base = target.rstrip("/")
        discovered: list[dict] = []
        highest_risk = "informational"
        risk_order = {"informational": 0, "low": 1, "medium": 2, "high": 3}

        for path in wordlist:
            url = base + path
            t_start = time.monotonic()
            resp = _make_request("GET", url, allowed_hosts=allowed_hosts, allow_redirects=False)
            if resp is None:
                continue

            status = getattr(resp, "status_code", 404)
            if status in (404, 400):
                continue

            elapsed_ms = round(_get_elapsed_seconds(resp, time.monotonic() - t_start) * 1000)
            headers = getattr(resp, "headers", {}) or {}
            content_type = headers.get("Content-Type", "")
            content_length = len(getattr(resp, "content", b"") or b"")

            path_lower = path.lower()
            if "admin" in path_lower or "debug" in path_lower:
                path_risk = "high"
            elif any(k in path_lower for k in ("swagger", "openapi", "api-docs")):
                path_risk = "medium"
            elif path_lower in ("/robots.txt", "/sitemap.xml"):
                path_risk = "low"
            else:
                path_risk = "informational"

            if risk_order.get(path_risk, 0) > risk_order.get(highest_risk, 0):
                highest_risk = path_risk

            entry = {
                "path": path,
                "url": url,
                "status_code": status,
                "content_type": content_type.split(";")[0].strip(),
                "content_length_bytes": content_length,
                "response_time_ms": elapsed_ms,
                "risk": path_risk,
            }

            if status == 200 and "swagger" in path_lower:
                try:
                    spec = json.loads(resp.text)
                    if isinstance(spec, dict) and "paths" in spec:
                        entry["api_spec_paths"] = list(spec["paths"].keys())[:20]
                except Exception:
                    pass

            discovered.append(entry)

        if not discovered:
            finding = "No accessible endpoints discovered on common paths."
            highest_risk = "informational"
        else:
            finding = f"{len(discovered)} endpoint(s) discovered: {', '.join(e['path'] for e in discovered[:5])}."

        return _build_result(
            tool=tool_name,
            status="success",
            target=target,
            finding=finding,
            evidence=discovered,
            risk_indicator=highest_risk,
            confidence="high" if discovered else "medium",
            recommendation="Review discovered endpoints for unintended exposure.",
            next_step="Analyze each discovered endpoint with analyze_http_response.",
        )

    except ValueError as exc:
        return _error_result(tool_name, target, str(exc))
    except Exception as exc:
        logger.exception("Unexpected error in %s", tool_name)
        return _error_result(tool_name, target, f"Unexpected error: {exc}")


def analyze_http_response(input_json: str) -> str:
    """Analyze HTTP status codes, headers, and response body."""
    tool_name = "analyze_http_response"
    target = ""
    try:
        params = _parse_input(input_json)
        target = _extract_target_url(params)
        if not target:
            return _error_result(tool_name, target, "Missing required parameter: 'target' or 'url'")

        method = params.get("method", "GET").upper()
        valid_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
        if method not in valid_methods:
            return _error_result(tool_name, target, f"Unsupported HTTP method '{method}'.")

        allowed_hosts = _resolve_allowed_hosts(params, target)
        if not _validate_scope(target, allowed_hosts):
            return _skipped_result(tool_name, target, "URL is out of authorized scope.")

        custom_headers = params.get("headers", {})
        body = params.get("body")
        kwargs: dict[str, Any] = {"allowed_hosts": allowed_hosts}
        if custom_headers:
            kwargs["headers"] = custom_headers
        if body:
            kwargs["data"] = body

        t_start = time.monotonic()
        response = _make_request(method, target, **kwargs)
        if response is None:
            return _error_result(tool_name, target, "Request failed or target unreachable.")

        elapsed_ms = round(_get_elapsed_seconds(response, time.monotonic() - t_start) * 1000)
        headers = _parse_headers(response)
        raw_headers = getattr(response, "headers", {}) or {}
        server = raw_headers.get("Server", headers.get("server", "not disclosed"))
        x_powered = raw_headers.get("X-Powered-By", headers.get("x-powered-by"))
        body_text = getattr(response, "text", "") or ""
        body_preview = body_text[:500]

        has_traceback = bool(re.search(r"Traceback \(most recent call last\)|NullPointerException|SQLSTATE", body_text, re.I))
        risk_indicator = "informational"
        if has_traceback:
            risk_indicator = "high"
        elif server and server != "not disclosed":
            risk_indicator = "low"

        evidence = [{
            "status_code": getattr(response, "status_code", 200),
            "response_time_ms": elapsed_ms,
            "content_type": raw_headers.get("Content-Type", ""),
            "server": server,
            "server_version": server if server != "not disclosed" else None,
            "x_powered_by": x_powered,
            "body_preview": body_preview,
            "has_traceback": has_traceback,
        }]

        finding = f"HTTP {getattr(response, 'status_code', 200)} response received in {elapsed_ms}ms."
        if has_traceback:
            finding += " Stack trace / debug error detected in body."
        elif server and server != "not disclosed":
            finding += f" Server header exposed: {server}."

        return _build_result(
            tool=tool_name,
            status="success",
            target=target,
            finding=finding,
            evidence=evidence,
            risk_indicator=risk_indicator,
            confidence="high",
            recommendation="Suppress stack traces and server version headers in production.",
            next_step="Run check_security_headers and check_sensitive_disclosure.",
        )

    except ValueError as exc:
        return _error_result(tool_name, target, str(exc))
    except Exception as exc:
        logger.exception("Unexpected error in %s", tool_name)
        return _error_result(tool_name, target, f"Unexpected error: {exc}")


def check_security_headers(input_json: str) -> str:
    """Check missing or misconfigured HTTP security headers."""
    tool_name = "check_security_headers"
    target = ""
    try:
        params = _parse_input(input_json)
        target = _extract_target_url(params)
        if not target:
            return _error_result(tool_name, target, "Missing required parameter: 'target' or 'url'")

        allowed_hosts = _resolve_allowed_hosts(params, target)
        if not _validate_scope(target, allowed_hosts):
            return _skipped_result(tool_name, target, "Target is out of authorized scope.")

        response = _make_request("GET", target, allowed_hosts=allowed_hosts)
        if response is None:
            return _error_result(tool_name, target, "Request failed or target unreachable.")

        raw_headers = getattr(response, "headers", {}) or {}
        # Case insensitive mapping
        headers_lower = {k.lower(): str(v) for k, v in raw_headers.items()}

        hsts = headers_lower.get("strict-transport-security")
        csp = headers_lower.get("content-security-policy")
        xcto = headers_lower.get("x-content-type-options")
        xfo = headers_lower.get("x-frame-options")
        server = headers_lower.get("server")

        evidence: list[dict] = []
        issues: list[str] = []
        highest_risk = "informational"

        # HSTS check
        if not hsts:
            issues.append("Missing Strict-Transport-Security")
            highest_risk = "high"
            evidence.append({"header": "Strict-Transport-Security", "status": "missing", "risk": "high"})
        else:
            evidence.append({"header": "Strict-Transport-Security", "status": "present", "value": hsts})

        # CSP check
        if not csp:
            issues.append("Missing Content-Security-Policy")
            highest_risk = "high"
            evidence.append({"header": "Content-Security-Policy", "status": "missing", "risk": "high"})
        else:
            evidence.append({"header": "Content-Security-Policy", "status": "present", "value": csp})

        # XCTO check
        if not xcto:
            issues.append("Missing X-Content-Type-Options")
            if highest_risk != "high":
                highest_risk = "medium"
            evidence.append({"header": "X-Content-Type-Options", "status": "missing", "risk": "medium"})
        elif xcto.lower() != "nosniff":
            issues.append("Misconfigured X-Content-Type-Options (not nosniff)")
            if highest_risk != "high":
                highest_risk = "medium"
            evidence.append({
                "header": "X-Content-Type-Options",
                "status": "misconfigured",
                "value": xcto,
                "issue": "x-content-type-options misconfigured (sniff)",
                "risk": "medium",
            })
        else:
            evidence.append({"header": "X-Content-Type-Options", "status": "present", "value": xcto})

        # XFO check
        if xfo:
            evidence.append({"header": "X-Frame-Options", "status": "present", "value": xfo})

        # Server header disclosure
        if server:
            issues.append(f"Server header disclosure: {server}")
            if highest_risk == "informational":
                highest_risk = "low"
            evidence.append({
                "header": "Server",
                "status": "information_disclosure",
                "value": server,
                "server_disclosure": True,
                "risk": "low",
            })

        if not issues:
            finding = "All recommended security headers are present and properly configured."
        else:
            finding = f"{len(issues)} security header issue(s) found: {'; '.join(issues)}."

        return _build_result(
            tool=tool_name,
            status="success",
            target=target,
            finding=finding,
            evidence=evidence,
            risk_indicator=highest_risk,
            confidence="high",
            recommendation="Add missing security headers and remove server disclosure headers.",
            next_step="Proceed with check_cors and check_cookie_security.",
        )

    except ValueError as exc:
        return _error_result(tool_name, target, str(exc))
    except Exception as exc:
        logger.exception("Unexpected error in %s", tool_name)
        return _error_result(tool_name, target, f"Unexpected error: {exc}")


def check_cors(input_json: str) -> str:
    """Inspect CORS configuration and identify unsafe origin policies."""
    tool_name = "check_cors"
    target = ""
    try:
        params = _parse_input(input_json)
        target = _extract_target_url(params)
        if not target:
            return _error_result(tool_name, target, "Missing required parameter: 'target' or 'url'")

        allowed_hosts = _resolve_allowed_hosts(params, target)
        if not _validate_scope(target, allowed_hosts):
            return _skipped_result(tool_name, target, "Target is out of authorized scope.")

        test_origins = params.get("test_origins")
        if not test_origins:
            single = params.get("test_origin")
            test_origins = [single] if single else ["https://evil.com", "null"]

        evidence: list[dict] = []
        highest_risk = "informational"
        risk_order = {"informational": 0, "low": 1, "medium": 2, "high": 3}

        for origin in test_origins:
            resp = _make_request(
                "OPTIONS",
                target,
                allowed_hosts=allowed_hosts,
                headers={"Origin": origin},
                allow_redirects=False,
            )
            if resp is None:
                resp = _make_request(
                    "GET",
                    target,
                    allowed_hosts=allowed_hosts,
                    headers={"Origin": origin},
                    allow_redirects=False,
                )
            if resp is None:
                continue

            raw_h = getattr(resp, "headers", {}) or {}
            headers_lower = {k.lower(): str(v) for k, v in raw_h.items()}
            acao = headers_lower.get("access-control-allow-origin", "")
            acac = headers_lower.get("access-control-allow-credentials", "").lower()

            wildcard = acao == "*"
            reflects = acao == origin
            has_creds = acac == "true"

            if (wildcard or reflects) and has_creds:
                risk = "high"
            elif origin == "null" and acao == "null":
                risk = "medium"
            elif wildcard:
                risk = "low"
            elif reflects:
                risk = "low"
            else:
                risk = "informational"

            if risk_order.get(risk, 0) > risk_order.get(highest_risk, 0):
                highest_risk = risk

            evidence.append({
                "origin_sent": origin,
                "acao": acao,
                "acac": acac,
                "reflects_origin": reflects,
                "wildcard": wildcard,
                "credentials_allowed": has_creds,
                "risk": risk,
            })

        if not evidence:
            return _error_result(tool_name, target, "CORS probe requests failed.")

        if highest_risk == "high":
            finding = "High-risk CORS misconfiguration: origin reflection or wildcard with credentials enabled."
        elif highest_risk == "medium":
            finding = "Medium-risk CORS misconfiguration: 'null' origin allowed."
        elif highest_risk == "low":
            finding = "Low-risk CORS configuration: wildcard origin without credentials."
        else:
            finding = "CORS policy is restricted to authorized origins."

        return _build_result(
            tool=tool_name,
            status="success",
            target=target,
            finding=finding,
            evidence=evidence,
            risk_indicator=highest_risk,
            confidence="high",
            recommendation="Do not reflect arbitrary origins and never allow credentials with wildcard.",
            next_step="Check authenticated endpoints for potential CORS exploitation.",
        )

    except ValueError as exc:
        return _error_result(tool_name, target, str(exc))
    except Exception as exc:
        logger.exception("Unexpected error in %s", tool_name)
        return _error_result(tool_name, target, f"Unexpected error: {exc}")


def check_cookie_security(input_json: str) -> str:
    """Inspect Secure, HttpOnly, and SameSite cookie attributes."""
    tool_name = "check_cookie_security"
    target = ""
    try:
        params = _parse_input(input_json)
        target = _extract_target_url(params)
        if not target:
            return _error_result(tool_name, target, "Missing required parameter: 'target' or 'url'")

        allowed_hosts = _resolve_allowed_hosts(params, target)
        if not _validate_scope(target, allowed_hosts):
            return _skipped_result(tool_name, target, "Target is out of authorized scope.")

        resp = _make_request("GET", target, allowed_hosts=allowed_hosts)
        if resp is None:
            return _error_result(tool_name, target, "Request failed or target unreachable.")

        is_https = target.lower().startswith("https://")
        raw_headers = getattr(resp, "headers", {}) or {}

        # Extract set-cookie strings
        set_cookie_headers: list[str] = []
        for k, v in raw_headers.items():
            if k.lower() == "set-cookie":
                set_cookie_headers.append(str(v))

        parsed_cookies: list[dict] = []
        for sc in set_cookie_headers:
            parsed = _parse_set_cookie_header(sc)
            if parsed:
                parsed_cookies.append(parsed)

        # Fallback to cookies dict if headers didn't yield parsed objects
        if not parsed_cookies and hasattr(resp, "cookies"):
            cookies_dict = {}
            if hasattr(resp.cookies, "items"):
                cookies_dict = dict(resp.cookies.items())
            elif hasattr(resp.cookies, "get_dict"):
                cookies_dict = resp.cookies.get_dict()
            for name, val in cookies_dict.items():
                parsed_cookies.append({
                    "name": name,
                    "value_preview": str(val)[:4] + "***",
                    "secure": False,
                    "httponly": False,
                    "samesite": "",
                })

        evidence: list[dict] = []
        highest_risk = "informational"
        issues: list[str] = []

        for c in parsed_cookies:
            name = c.get("name", "unknown")
            secure = c.get("secure", False)
            httponly = c.get("httponly", False)
            samesite = c.get("samesite", "")

            cookie_issues = []
            if is_https and not secure:
                cookie_issues.append("missing_secure")
                highest_risk = "high"

            if not httponly:
                cookie_issues.append("missing_httponly")
                if highest_risk != "high":
                    highest_risk = "medium"

            if samesite and samesite.lower() == "none" and not secure:
                cookie_issues.append("samesite_none_without_secure")
                highest_risk = "high"

            if cookie_issues:
                issues.append(f"{name}: {', '.join(cookie_issues)}")

            evidence.append({
                "name": name,
                "secure": secure,
                "httponly": httponly,
                "samesite": samesite,
                "issues": cookie_issues,
                "missing_httponly": not httponly,
                "missing_secure": not secure,
            })

        if not evidence:
            finding = "No cookies set by this endpoint."
        elif not issues:
            finding = f"{len(evidence)} cookie(s) inspected. All security attributes configured correctly."
        else:
            finding = f"{len(evidence)} cookie(s) inspected. Issues found: {'; '.join(issues)}."

        return _build_result(
            tool=tool_name,
            status="success",
            target=target,
            finding=finding,
            evidence=evidence,
            risk_indicator=highest_risk,
            confidence="high" if evidence else "informational",
            recommendation="Set Secure and HttpOnly flags on all session cookies with SameSite=Strict or Lax.",
            next_step="Proceed to test authentication mechanisms with check_authentication.",
        )

    except ValueError as exc:
        return _error_result(tool_name, target, str(exc))
    except Exception as exc:
        logger.exception("Unexpected error in %s", tool_name)
        return _error_result(tool_name, target, f"Unexpected error: {exc}")


def check_sql_injection(input_json: str) -> str:
    """Perform controlled and non-destructive SQL injection validation."""
    tool_name = "check_sql_injection"
    target = ""
    try:
        params = _parse_input(input_json)
        target = _extract_target_url(params)
        if not target:
            return _error_result(tool_name, target, "Missing required parameter: 'target' or 'url'")

        allowed_hosts = _resolve_allowed_hosts(params, target)
        if not _validate_scope(target, allowed_hosts):
            return _skipped_result(tool_name, target, "Target is out of authorized scope.")

        parameters = params.get("parameters")
        if not parameters:
            param_key = params.get("param")
            if param_key:
                parameters = {param_key: "1"}
            else:
                parameters = {"id": "1"}

        method = params.get("method", "GET").upper()
        sql_error_patterns = [
            re.compile(p, re.IGNORECASE) for p in [
                r"sql syntax", r"syntax error", r"mysql", r"sqlite", r"postgresql",
                r"ora-\d{5}", r"odbc", r"sql server", r"warning: mysql",
            ]
        ]

        # Establish baseline
        t0 = time.monotonic()
        baseline_resp = _make_request(
            method,
            target,
            allowed_hosts=allowed_hosts,
            params=parameters if method == "GET" else None,
            data=parameters if method != "GET" else None,
        )
        baseline_time = _get_elapsed_seconds(baseline_resp, time.monotonic() - t0)
        baseline_len = len(getattr(baseline_resp, "content", b"") or b"")

        payloads = [
            ("single_quote", "'"),
            ("tautology", "1' OR '1'='1"),
            ("time_based", "1' AND SLEEP(2)--"),
        ]

        evidence: list[dict] = []
        highest_risk = "informational"
        confidence = "low"

        for p_name, payload in payloads:
            test_params = dict(parameters)
            for k in test_params:
                test_params[k] = payload

            t1 = time.monotonic()
            test_resp = _make_request(
                method,
                target,
                allowed_hosts=allowed_hosts,
                params=test_params if method == "GET" else None,
                data=test_params if method != "GET" else None,
            )
            if test_resp is None:
                continue

            test_time = _get_elapsed_seconds(test_resp, time.monotonic() - t1)
            test_body = getattr(test_resp, "text", "") or ""
            test_len = len(getattr(test_resp, "content", b"") or b"")
            len_diff = abs(test_len - baseline_len)
            time_diff = test_time - baseline_time

            has_sql_error = any(p.search(test_body) for p in sql_error_patterns)
            has_time_delay = test_time > 1.5 or time_diff > 1.5
            has_len_diff = len_diff > 100

            if has_sql_error:
                highest_risk = "high"
                confidence = "high"
                evidence.append({
                    "payload": payload,
                    "type": "error_based",
                    "error_found": True,
                    "body_preview": test_body[:150],
                })
            elif has_time_delay:
                if highest_risk != "high":
                    highest_risk = "medium"
                if confidence != "high":
                    confidence = "medium"
                evidence.append({
                    "payload": payload,
                    "type": "time_based",
                    "elapsed_seconds": test_time,
                    "time_delay_detected": True,
                })
            elif has_len_diff:
                if highest_risk == "informational":
                    highest_risk = "low"
                evidence.append({
                    "payload": payload,
                    "type": "length_difference",
                    "length_diff": len_diff,
                    "size_difference": True,
                })

        if not evidence:
            finding = "No SQL injection indicators detected."
        else:
            finding = f"SQL injection indicators detected with {len(evidence)} payload(s)."

        return _build_result(
            tool=tool_name,
            status="success",
            target=target,
            finding=finding,
            evidence=evidence,
            risk_indicator=highest_risk,
            confidence=confidence,
            recommendation="Use parameterized queries and prepared statements.",
            next_step="AI agent should evaluate confidence and report findings.",
        )

    except ValueError as exc:
        return _error_result(tool_name, target, str(exc))
    except Exception as exc:
        logger.exception("Unexpected error in %s", tool_name)
        return _error_result(tool_name, target, f"Unexpected error: {exc}")


def check_command_injection(input_json: str) -> str:
    """Perform safe command injection validation without executing harmful commands."""
    tool_name = "check_command_injection"
    target = ""
    _PROBE = "RedTeamProbe2024"
    try:
        params = _parse_input(input_json)
        target = _extract_target_url(params)
        if not target:
            return _error_result(tool_name, target, "Missing required parameter: 'target' or 'url'")

        allowed_hosts = _resolve_allowed_hosts(params, target)
        if not _validate_scope(target, allowed_hosts):
            return _skipped_result(tool_name, target, "Target is out of authorized scope.")

        parameters = params.get("parameters")
        if not parameters:
            param_key = params.get("param")
            if param_key:
                parameters = {param_key: "127.0.0.1"}
            else:
                parameters = {"host": "127.0.0.1"}

        method = params.get("method", "POST").upper()

        payloads = [
            ("echo_probe", f"; echo {_PROBE}"),
            ("time_based", "; sleep 2"),
        ]

        evidence: list[dict] = []
        highest_risk = "informational"
        confidence = "low"

        for p_name, payload in payloads:
            test_params = dict(parameters)
            for k in test_params:
                test_params[k] = str(test_params[k]) + payload

            t1 = time.monotonic()
            resp = _make_request(
                method,
                target,
                allowed_hosts=allowed_hosts,
                data=test_params if method != "GET" else None,
                params=test_params if method == "GET" else None,
            )
            if resp is None:
                continue

            elapsed = _get_elapsed_seconds(resp, time.monotonic() - t1)
            body = getattr(resp, "text", "") or ""

            probe_reflected = _PROBE in body
            time_delay = elapsed > 1.5 and "time" in p_name

            if probe_reflected:
                highest_risk = "high"
                confidence = "high"
                evidence.append({
                    "payload": payload,
                    "probe_reflected": True,
                    "output_preview": body[:150],
                })
            elif time_delay:
                if highest_risk != "high":
                    highest_risk = "medium"
                if confidence != "high":
                    confidence = "medium"
                evidence.append({
                    "payload": payload,
                    "time_delay_detected": True,
                    "elapsed_seconds": elapsed,
                })

        if not evidence:
            finding = "No command injection indicators detected."
        else:
            finding = f"Command injection indicators detected with {len(evidence)} payload(s)."

        return _build_result(
            tool=tool_name,
            status="success",
            target=target,
            finding=finding,
            evidence=evidence,
            risk_indicator=highest_risk,
            confidence=confidence,
            recommendation="Never pass untrusted user input directly to system command execution.",
            next_step="AI agent should report potential command execution vulnerabilities.",
        )

    except ValueError as exc:
        return _error_result(tool_name, target, str(exc))
    except Exception as exc:
        logger.exception("Unexpected error in %s", tool_name)
        return _error_result(tool_name, target, f"Unexpected error: {exc}")


def check_idor(input_json: str) -> str:
    """Compare resource access permissions using test accounts."""
    tool_name = "check_idor"
    target = ""
    try:
        params = _parse_input(input_json)
        target = _extract_target_url(params)
        if not target:
            return _error_result(tool_name, target, "Missing required parameter: 'target' or 'url'")

        allowed_hosts = _resolve_allowed_hosts(params, target)
        if not _validate_scope(target, allowed_hosts):
            return _skipped_result(tool_name, target, "Target is out of authorized scope.")

        token_a = params.get("user_a_token") or (params.get("account_a", {}).get("token")) or "tokenA"
        token_b = params.get("user_b_token")
        if token_b is None:
            token_b = (params.get("account_b", {}).get("token")) or ""

        # Request A with token A (owner)
        headers_a = {"Authorization": f"Bearer {token_a}"} if token_a else {}
        resp_a = _make_request("GET", target, allowed_hosts=allowed_hosts, headers=headers_a)

        # Request A with token B (unauthorized or cross-account)
        headers_b = {"Authorization": f"Bearer {token_b}"} if token_b else {}
        resp_b = _make_request("GET", target, allowed_hosts=allowed_hosts, headers=headers_b)

        status_a = getattr(resp_a, "status_code", None)
        status_b = getattr(resp_b, "status_code", None)
        body_a = getattr(resp_a, "text", "") or ""
        body_b = getattr(resp_b, "text", "") or ""

        evidence = [
            {"request": "User A (owner)", "status_code": status_a, "body_length": len(body_a)},
            {"request": "User B / Unauthenticated", "status_code": status_b, "body_length": len(body_b)},
        ]

        highest_risk = "informational"
        confidence = "low"

        if status_b == 200:
            if not token_b:
                highest_risk = "high"
                confidence = "high"
                finding = "IDOR / Missing Authorization: Unauthenticated request received HTTP 200 on protected resource."
            elif body_a == body_b:
                highest_risk = "high"
                confidence = "high"
                finding = "IDOR detected: User B accessed User A's resource with identical response."
            else:
                highest_risk = "high"
                confidence = "medium"
                finding = "Potential IDOR: User B received HTTP 200 on User A's resource (partial/different body)."
        elif status_b in (401, 403):
            highest_risk = "informational"
            confidence = "high"
            finding = f"Access control enforced properly: Unauthorized request received HTTP {status_b}."
        else:
            finding = f"Access control returned HTTP {status_b}."

        return _build_result(
            tool=tool_name,
            status="success",
            target=target,
            finding=finding,
            evidence=evidence,
            risk_indicator=highest_risk,
            confidence=confidence,
            recommendation="Implement strict server-side resource ownership checks.",
            next_step="Proceed to test other object identifier endpoints.",
        )

    except ValueError as exc:
        return _error_result(tool_name, target, str(exc))
    except Exception as exc:
        logger.exception("Unexpected error in %s", tool_name)
        return _error_result(tool_name, target, f"Unexpected error: {exc}")


def check_authentication(input_json: str) -> str:
    """Inspect authentication and authorization behavior using controlled requests."""
    tool_name = "check_authentication"
    target = ""
    try:
        params = _parse_input(input_json)
        target = _extract_target_url(params)
        if not target:
            return _error_result(tool_name, target, "Missing required parameter: 'target' or 'protected_url'")

        allowed_hosts = _resolve_allowed_hosts(params, target)
        if not _validate_scope(target, allowed_hosts):
            return _skipped_result(tool_name, target, "Target is out of authorized scope.")

        valid_token = params.get("valid_token", "")
        evidence: list[dict] = []
        highest_risk = "informational"
        confidence = "high"

        # Check JWT for alg:none
        if valid_token:
            parts = valid_token.removeprefix("Bearer ").strip().split(".")
            if len(parts) >= 2:
                try:
                    padding = 4 - len(parts[0]) % 4
                    header_str = base64.urlsafe_b64decode(parts[0] + "=" * (padding % 4)).decode(errors="ignore")
                    jwt_header = json.loads(header_str)
                    if isinstance(jwt_header, dict) and jwt_header.get("alg", "").lower() == "none":
                        highest_risk = "high"
                        evidence.append({
                            "type": "jwt_vulnerability",
                            "alg": "none",
                            "risk": "high",
                            "issue": "JWT alg:none allowed",
                        })
                except Exception:
                    pass

        # Unauthenticated request
        resp_no_auth = _make_request("GET", target, allowed_hosts=allowed_hosts)
        status_no_auth = getattr(resp_no_auth, "status_code", None)
        evidence.append({"request": "no_auth", "status_code": status_no_auth})

        # Invalid token request
        invalid_headers = {"Authorization": "Bearer invalid_garbage_token_12345"}
        resp_invalid = _make_request("GET", target, allowed_hosts=allowed_hosts, headers=invalid_headers)
        status_invalid = getattr(resp_invalid, "status_code", None)
        evidence.append({"request": "invalid_token", "status_code": status_invalid})

        # Valid token request
        if valid_token:
            auth_header = valid_token if valid_token.startswith("Bearer ") else f"Bearer {valid_token}"
            resp_valid = _make_request("GET", target, allowed_hosts=allowed_hosts, headers={"Authorization": auth_header})
            status_valid = getattr(resp_valid, "status_code", None)
            evidence.append({"request": "valid_token", "status_code": status_valid})

        if status_invalid == 200:
            highest_risk = "high"
            finding = "Broken authentication: Invalid token accepted with HTTP 200."
        elif status_no_auth == 200:
            highest_risk = "high"
            finding = "Missing authentication: Protected endpoint returns HTTP 200 without credentials."
        elif highest_risk == "high":
            finding = "JWT algorithm 'none' vulnerability detected."
        else:
            finding = f"Authentication controls enforced correctly (Unauthenticated: {status_no_auth}, Invalid: {status_invalid})."

        return _build_result(
            tool=tool_name,
            status="success",
            target=target,
            finding=finding,
            evidence=evidence,
            risk_indicator=highest_risk,
            confidence=confidence,
            recommendation="Ensure all protected endpoints validate tokens and reject alg:none.",
            next_step="Proceed with authorization and IDOR checks.",
        )

    except ValueError as exc:
        return _error_result(tool_name, target, str(exc))
    except Exception as exc:
        logger.exception("Unexpected error in %s", tool_name)
        return _error_result(tool_name, target, f"Unexpected error: {exc}")


def check_sensitive_disclosure(input_json: str) -> str:
    """Identify potentially sensitive information exposed through HTTP responses."""
    tool_name = "check_sensitive_disclosure"
    target = ""
    try:
        params = _parse_input(input_json)
        target = _extract_target_url(params)
        if not target:
            return _error_result(tool_name, target, "Missing required parameter: 'target' or 'url'")

        allowed_hosts = _resolve_allowed_hosts(params, target)
        if not _validate_scope(target, allowed_hosts):
            return _skipped_result(tool_name, target, "Target is out of authorized scope.")

        resp = _make_request("GET", target, allowed_hosts=allowed_hosts)
        if resp is None:
            return _error_result(tool_name, target, "Request failed or target unreachable.")

        body = getattr(resp, "text", "") or ""
        evidence: list[dict] = []
        highest_risk = "informational"
        risk_order = {"informational": 0, "low": 1, "medium": 2, "high": 3}

        patterns = [
            ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}"), "high"),
            ("jwt_token", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+"), "high"),
            ("stack_trace", re.compile(r"NullPointerException|Traceback \(most recent call last\)|Exception in thread"), "medium"),
            ("private_ip", re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"), "low"),
            ("email_address", re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"), "low"),
        ]

        for p_name, regex, sev in patterns:
            match = regex.search(body)
            if match:
                matched_val = match.group(0)
                preview = matched_val[:4] + "***" if len(matched_val) > 4 else "***"
                if risk_order.get(sev, 0) > risk_order.get(highest_risk, 0):
                    highest_risk = sev
                evidence.append({
                    "type": p_name,
                    "preview": preview,
                    "matched_sample": matched_val if p_name in ("private_ip", "email_address") else preview,
                    "risk": sev,
                })

        if not evidence:
            finding = "No sensitive information patterns detected in response."
        else:
            names = [e["type"] for e in evidence]
            finding = f"Sensitive information disclosure detected: {', '.join(names)}."

        return _build_result(
            tool=tool_name,
            status="success",
            target=target,
            finding=finding,
            evidence=evidence,
            risk_indicator=highest_risk,
            confidence="high",
            recommendation="Sanitize responses and remove sensitive tokens, keys, and internal IP addresses.",
            next_step="AI agent should report any exposed credentials or sensitive artifacts.",
        )

    except ValueError as exc:
        return _error_result(tool_name, target, str(exc))
    except Exception as exc:
        logger.exception("Unexpected error in %s", tool_name)
        return _error_result(tool_name, target, f"Unexpected error: {exc}")
