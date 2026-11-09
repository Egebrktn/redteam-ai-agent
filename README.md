# AI Supported Autonomous Red Team System — Web & API Security Tools

![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue) ![License: MIT](https://img.shields.io/badge/License-MIT-green) ![Status: Authorized Testing Only](https://img.shields.io/badge/Status-Authorized%20Testing%20Only-red)

---

> [!CAUTION]
> **Legal Disclaimer:** This module is designed exclusively for use on systems for which explicit written authorization has been obtained. Unauthorized use against systems you do not own or have permission to test is **illegal and unethical**. The authors accept no liability for misuse of this software. Always obtain written authorization before conducting any security assessment.

---

## Overview

`tools.py` is the **execution and evidence collection layer** for an AI-powered autonomous red team agent. The AI agent (LLM) decides which tool to invoke, interprets the JSON output, selects the next testing step, and generates the final security report.

The module itself returns **factual observations** — it does not make vulnerability declarations or generate reports. All decision-making and reporting is delegated to the AI agent layer.

---

## Architecture

```
AI Agent (LLM)
     │
     │  JSON string input / JSON string output
     ▼
tools.py (11 public functions)
     │
     ▼
Shared HTTP Session + Rate Limiter + Scope Enforcement
```

---

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd projeyönetimi

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## Configuration

The `allowed_hosts` list **must be passed explicitly in every function call**. There are no defaults. This is a deliberate safety constraint — every HTTP request is validated against the caller-supplied scope.

```python
import tools

# Always pass allowed_hosts that match your authorized scope
input_data = {
    "url": "https://target.example.com",
    "allowed_hosts": ["target.example.com"]
}
```

You can also configure the module-level `ToolConfig` object to adjust timeout durations and rate-limiting behaviour (e.g., maximum requests per second). Refer to the `ToolConfig` class docstring in `tools.py` for available fields.

---

## Authorization Scope

The module enforces strict scope controls at every HTTP call boundary:

- **Always pass** an `allowed_hosts` list that matches your authorized targets.
- **Subdomain matching is supported**: e.g., `example.com` in `allowed_hosts` will also cover `api.example.com`.
- **Private/loopback IPs are blocked** (e.g., `127.0.0.1`, `10.x.x.x`, `192.168.x.x`) unless they are explicitly present in `allowed_hosts`.
- **Redirects to out-of-scope hosts are blocked automatically** — the module will not silently follow a redirect outside the authorized scope.
- Any request that falls outside the authorized scope returns `"status": "skipped"` with an explanatory message — no HTTP request is made.

---

## Function Reference

### `validate_target`

**Purpose:** Validate target URL, hostname, protocol and authorized scope before testing. Must be called first.

**Input JSON:**
```json
{
  "url": "https://target.example.com",
  "allowed_hosts": ["target.example.com"]
}
```

**Output JSON:**
```json
{
  "tool": "validate_target",
  "status": "success",
  "target": "https://target.example.com",
  "finding": "Target is reachable via HTTPS. TLS certificate valid. Server: nginx. Response time: 142ms.",
  "evidence": [
    {
      "type": "reachability",
      "status_code": 200,
      "tls_valid": true,
      "response_time_ms": 142,
      "server_header": "nginx",
      "redirect_count": 0
    }
  ],
  "risk_indicator": "informational",
  "confidence": "high",
  "recommendation": "Proceed with security assessment.",
  "next_step": "Call discover_endpoints to map the attack surface."
}
```

**Risk indicators:** `informational`, `error`

---

### `discover_endpoints`

**Purpose:** Discover accessible Web and API endpoints through safe HTTP requests and exposed API documentation.

**Input JSON:**
```json
{
  "base_url": "https://target.example.com",
  "allowed_hosts": ["target.example.com"],
  "wordlist": ["api", "v1", "admin", "docs"]
}
```

**Output JSON:**
```json
{
  "tool": "discover_endpoints",
  "status": "success",
  "target": "https://target.example.com",
  "finding": "4 endpoints discovered. Admin panel found at /admin. API documentation exposed at /docs.",
  "evidence": [
    {"path": "/admin", "status_code": 200, "content_type": "text/html", "response_time_ms": 89},
    {"path": "/docs",  "status_code": 200, "content_type": "application/json", "response_time_ms": 54}
  ],
  "risk_indicator": "high",
  "confidence": "high",
  "recommendation": "Restrict /admin to authorized IPs. Disable public API documentation in production.",
  "next_step": "Analyze each discovered endpoint with analyze_http_response."
}
```

**Risk indicators:** `informational`, `low`, `medium`, `high`

---

### `analyze_http_response`

**Purpose:** Analyze HTTP status codes, headers, cookies, response body and response behavior.

**Input JSON:**
```json
{
  "url": "https://target.example.com/api/users",
  "method": "GET",
  "headers": {"Authorization": "Bearer token123"},
  "allowed_hosts": ["target.example.com"]
}
```

**Output JSON:**
```json
{
  "tool": "analyze_http_response",
  "status": "success",
  "target": "https://target.example.com/api/users",
  "finding": "200 OK response in 95ms. Content-Type: application/json. Server: Apache/2.4.52 version exposed. No debug info detected.",
  "evidence": [
    {
      "status_code": 200,
      "response_time_ms": 95,
      "content_type": "application/json",
      "server": "Apache/2.4.52",
      "x_powered_by": null,
      "body_preview": "{\"users\": [...]}",
      "debug_info_detected": false
    }
  ],
  "risk_indicator": "low",
  "confidence": "high",
  "recommendation": "Remove server version from Server header.",
  "next_step": "Run check_security_headers and check_sensitive_disclosure on this endpoint."
}
```

**Risk indicators:** `informational`, `low`, `medium`, `high`

---

### `check_security_headers`

**Purpose:** Check missing or incorrectly configured HTTP security headers.

**Input JSON:**
```json
{
  "url": "https://target.example.com",
  "allowed_hosts": ["target.example.com"]
}
```

**Output JSON:**
```json
{
  "tool": "check_security_headers",
  "status": "success",
  "target": "https://target.example.com",
  "finding": "3 security header issues found. Missing: Content-Security-Policy. Missing: Permissions-Policy. X-Frame-Options present and correct.",
  "evidence": [
    {"header": "Strict-Transport-Security", "status": "present", "value": "max-age=31536000; includeSubDomains", "compliant": true},
    {"header": "Content-Security-Policy",   "status": "missing", "value": null, "compliant": false}
  ],
  "risk_indicator": "high",
  "confidence": "high",
  "recommendation": "Add Content-Security-Policy header. Add Permissions-Policy header.",
  "next_step": "Check cookie security with check_cookie_security."
}
```

**Risk indicators:** `informational`, `low`, `medium`, `high`

---

### `check_cors`

**Purpose:** Inspect CORS configuration and identify potentially unsafe origin policies.

**Input JSON:**
```json
{
  "url": "https://target.example.com/api",
  "test_origins": ["https://evil.com", "null"],
  "allowed_hosts": ["target.example.com"]
}
```

**Output JSON:**
```json
{
  "tool": "check_cors",
  "status": "success",
  "target": "https://target.example.com/api",
  "finding": "CORS misconfiguration detected. Origin 'https://evil.com' is reflected with Access-Control-Allow-Credentials: true.",
  "evidence": [
    {
      "origin_sent": "https://evil.com",
      "acao_header": "https://evil.com",
      "acac_header": "true",
      "reflects_origin": true,
      "risk": "high"
    }
  ],
  "risk_indicator": "high",
  "confidence": "high",
  "recommendation": "Implement strict origin allowlist. Never combine wildcard origin with credentials.",
  "next_step": "Test authenticated endpoints for CORS impact with check_authentication."
}
```

**Risk indicators:** `informational`, `low`, `medium`, `high`

---

### `check_cookie_security`

**Purpose:** Inspect `Secure`, `HttpOnly` and `SameSite` cookie attributes.

**Input JSON:**
```json
{
  "url": "https://target.example.com/login",
  "allowed_hosts": ["target.example.com"]
}
```

**Output JSON:**
```json
{
  "tool": "check_cookie_security",
  "status": "success",
  "target": "https://target.example.com/login",
  "finding": "2 cookies found. Session cookie missing HttpOnly flag. Auth cookie missing Secure flag on HTTPS endpoint.",
  "evidence": [
    {
      "name": "sessionid",
      "secure": false,
      "httponly": false,
      "samesite": "Lax",
      "likely_auth_cookie": true,
      "issues": ["missing_secure", "missing_httponly"]
    }
  ],
  "risk_indicator": "high",
  "confidence": "high",
  "recommendation": "Set Secure, HttpOnly flags on all session cookies. Use SameSite=Strict or Lax.",
  "next_step": "Test authentication behavior with check_authentication."
}
```

**Risk indicators:** `informational`, `low`, `medium`, `high`

---

### `check_sql_injection`

**Purpose:** Perform controlled, non-destructive SQL injection validation on authorized test parameters.

**Input JSON:**
```json
{
  "url": "https://target.example.com/api/users",
  "method": "GET",
  "parameters": {"id": "1"},
  "allowed_hosts": ["target.example.com"]
}
```

**Output JSON:**
```json
{
  "tool": "check_sql_injection",
  "status": "success",
  "target": "https://target.example.com/api/users",
  "finding": "SQL injection indicators detected in parameter 'id'. Response contains SQL syntax error message with single-quote payload.",
  "evidence": [
    {
      "parameter": "id",
      "payload": "'",
      "baseline_status": 200,
      "payload_status": 500,
      "error_keywords_found": ["SQL syntax", "mysql_fetch"],
      "response_length_diff": 342,
      "time_delta_seconds": 0.1
    }
  ],
  "risk_indicator": "high",
  "confidence": "high",
  "recommendation": "Use parameterized queries / prepared statements. Sanitize all user input.",
  "next_step": "Report to AI agent for exploitation assessment. Test additional parameters."
}
```

**Risk indicators:** `informational`, `low`, `medium`, `high`

---

### `check_command_injection`

**Purpose:** Perform safe command injection validation without executing harmful commands.

**Input JSON:**
```json
{
  "url": "https://target.example.com/api/ping",
  "method": "POST",
  "parameters": {"host": "127.0.0.1"},
  "allowed_hosts": ["target.example.com"]
}
```

**Output JSON:**
```json
{
  "tool": "check_command_injection",
  "status": "success",
  "target": "https://target.example.com/api/ping",
  "finding": "Command injection probe string found in response body for parameter 'host'. Payload '; echo RedTeamProbe2024' reflected in response.",
  "evidence": [
    {
      "parameter": "host",
      "payload": "; echo RedTeamProbe2024",
      "probe_found_in_response": true,
      "response_body_preview": "PING 127.0.0.1 ... RedTeamProbe2024",
      "time_delta_seconds": 0.08
    }
  ],
  "risk_indicator": "high",
  "confidence": "high",
  "recommendation": "Never pass user input to OS command execution functions. Use safe APIs.",
  "next_step": "Escalate finding to AI agent. Test additional parameters."
}
```

**Risk indicators:** `informational`, `low`, `medium`, `high`

---

### `check_idor`

**Purpose:** Compare resource access permissions using explicitly supplied authorized test accounts.

**Input JSON:**
```json
{
  "url": "https://target.example.com/api/users/{id}/profile",
  "account_a": {"id": "101", "token": "tokenA"},
  "account_b": {"id": "102", "token": "tokenB"},
  "allowed_hosts": ["target.example.com"]
}
```

**Output JSON:**
```json
{
  "tool": "check_idor",
  "status": "success",
  "target": "https://target.example.com/api/users/101/profile",
  "finding": "Potential IDOR: Account B successfully accessed Account A's resource with status 200. Response body length matches owner's response.",
  "evidence": [
    {"request": "A accesses own resource",          "status_code": 200, "body_length": 342},
    {"request": "B accesses A resource (cross-account)", "status_code": 200, "body_length": 338, "suspicion": "similar body length to owner response"}
  ],
  "risk_indicator": "high",
  "confidence": "medium",
  "recommendation": "Implement server-side authorization checks verifying resource ownership.",
  "next_step": "AI agent should escalate and manually verify IDOR with actual data comparison."
}
```

**Risk indicators:** `informational`, `low`, `medium`, `high`

---

### `check_authentication`

**Purpose:** Inspect authentication and authorization behavior using controlled test requests.

**Input JSON:**
```json
{
  "protected_url": "https://target.example.com/api/admin",
  "login_url": "https://target.example.com/api/login",
  "valid_token": "Bearer eyJhbGc...",
  "allowed_hosts": ["target.example.com"]
}
```

**Output JSON:**
```json
{
  "tool": "check_authentication",
  "status": "success",
  "target": "https://target.example.com/api/admin",
  "finding": "Authentication enforced correctly. Unauthenticated → 401, Invalid token → 401, Valid token → 200. No broken auth detected.",
  "evidence": [
    {"description": "No auth",       "status_code": 401, "auth_header_sent": null},
    {"description": "Invalid token", "status_code": 401, "auth_header_sent": "Bearer invalid_test_token_1234"},
    {"description": "Valid token",   "status_code": 200, "auth_header_sent": "[REDACTED]"}
  ],
  "risk_indicator": "informational",
  "confidence": "high",
  "recommendation": "Authentication controls appear correctly enforced.",
  "next_step": "Test for IDOR with check_idor."
}
```

**Risk indicators:** `informational`, `low`, `medium`, `high`

---

### `check_sensitive_disclosure`

**Purpose:** Identify potentially sensitive information exposed through HTTP responses.

**Input JSON:**
```json
{
  "url": "https://target.example.com/api/users/1",
  "allowed_hosts": ["target.example.com"]
}
```

**Output JSON:**
```json
{
  "tool": "check_sensitive_disclosure",
  "status": "success",
  "target": "https://target.example.com/api/users/1",
  "finding": "2 sensitive data patterns found. AWS access key pattern detected in response body. Internal IP address exposed.",
  "evidence": [
    {"type": "aws_key",    "location": "body", "preview": "AKIA***",        "risk": "high"},
    {"type": "private_ip", "location": "body", "preview": "192.168.1.100",  "risk": "low"}
  ],
  "risk_indicator": "high",
  "confidence": "high",
  "recommendation": "Remove all credentials from API responses. Never expose internal network topology.",
  "next_step": "Escalate AWS key finding immediately. Test other endpoints for similar exposure."
}
```

**Risk indicators:** `informational`, `low`, `medium`, `high`

---

## Running Tests

```bash
# Run all tests (unit tests are mocked; integration tests use localhost only)
python -m unittest -v test_tools

# Run a specific test class with pytest (optional)
python -m pytest test_tools.py::TestCheckSqlInjection -v

# Run with coverage (requires optional pytest-cov)
pip install pytest-cov
python -m pytest test_tools.py --cov=tools --cov-report=term-missing
```

> [!NOTE]
> Unit tests mock HTTP calls. `TestLocalHttpIntegration` starts a temporary server bound only to `127.0.0.1` and exercises the real HTTP request path against it. Integration tests do not contact external systems.

---

## Extending the Module

To add a new tool function, follow these steps:

1. Create a new **public function** following the `str → str` interface (JSON string in, JSON string out).
2. Use `_parse_input()` to safely deserialize and validate the input JSON.
3. Use `_validate_scope()` before making **any** HTTP request to enforce authorization boundaries.
4. Use `_make_request()` for all HTTP calls — this ensures rate limiting, timeout, and redirect controls are applied uniformly.
5. Use `_build_result()` to format the output into the standard result schema.
6. Add corresponding **tests** in `test_tools.py` covering both success and out-of-scope cases.

---

## AI Agent Integration

The AI agent (LLM) integrates with `tools.py` as follows:

```python
import tools

# 1. Always call validate_target first
result = tools.validate_target('{"url": "https://target.example.com", "allowed_hosts": ["target.example.com"]}')

# 2. Parse and interpret the JSON output
import json
data = json.loads(result)

# 3. Use risk_indicator, confidence, and next_step to select the next action
if data["status"] == "success":
    print(data["next_step"])   # AI agent reads this to plan next call

# 4. Accumulate evidence across tool calls
evidence_log = []
evidence_log.extend(data["evidence"])

# 5. Generate the final report from collected evidence
# (report generation is the responsibility of the AI agent layer)
```

**Integration guidelines for the AI agent:**

- **Always call `validate_target` first** to confirm scope and reachability before proceeding.
- Feed JSON input → receive JSON output for every tool call.
- Interpret `risk_indicator` and `confidence` to prioritize findings.
- Follow the `next_step` hint to decide the subsequent tool invocation.
- Accumulate `evidence` arrays across all tool calls to build the full finding set.
- Generate the final security report from the collected evidence at the end of the assessment.

---

## Security Constraints Summary

The module will **never**:

- Make any HTTP request to a host not present in the caller-supplied `allowed_hosts` list.
- Follow redirects to hosts outside the authorized scope.
- Connect to private/loopback IP ranges unless explicitly authorized in `allowed_hosts`.
- Execute OS commands, spawn subprocesses, or interact with the local filesystem beyond logging.
- Store, log, or transmit credentials, tokens, or secrets (all auth material is redacted in output).
- Perform destructive operations (no `DELETE`, no data modification payloads).
- Automatically escalate or exploit any finding — all escalation decisions are delegated to the AI agent.
- Generate vulnerability reports or severity ratings — factual observations only.
- Exceed the configured rate limit to avoid causing denial-of-service conditions on the target.
- Operate without an explicit `allowed_hosts` list — there are no default targets.
