# main.py - AI Orchestrator ve Reporter Modülü
# Bu dosya projenin ana giriş noktasıdır.
# Orchestrator AI burada çalışır, tools.py içindeki araçlardan hangisini kullanacağına karar verir.
# Tüm test adımları bittiğinde toplanan çıktıları Reporter AI'a göndererek nihai güvenlik raporunu üretir.

import inspect
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from dotenv import load_dotenv
from openai import OpenAI, OpenAIError
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt

import tools

# ---------------------------------------------------------------------------
# 0. External Contract & Automatic Adapter for tools.py
# ---------------------------------------------------------------------------
def _make_json_tool_adapter(fn: Callable[[str], str]) -> Callable[..., str]:
    """
    Wraps a tools.py function that expects a single `input_json: str` parameter
    so that it can be invoked seamlessly via `tool_callable(**tool_args)`.
    """
    sig = inspect.signature(fn)
    params = list(sig.parameters.values())

    def _wrapped(**kwargs: Any) -> str:
        # If the underlying function takes a single `input_json` string (like Ceyda's tools.py)
        if len(params) == 1 and params[0].kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        ):
            # If LLM already passed {"input_json": "..."}
            if "input_json" in kwargs and len(kwargs) == 1 and isinstance(kwargs["input_json"], str):
                return fn(kwargs["input_json"])
            return fn(json.dumps(kwargs, ensure_ascii=False))
        # Otherwise call directly with keyword arguments
        return fn(**kwargs)

    return _wrapped


if hasattr(tools, "TOOL_MAP") and hasattr(tools, "TOOLS_DESCRIPTION"):
    from tools import TOOL_MAP, TOOLS_DESCRIPTION  # type: ignore[attr-defined]
else:
    # Build TOOL_MAP & TOOLS_DESCRIPTION dynamically from tools.py functions
    _RAW_TOOLS: list[str] = [
        "validate_target",
        "discover_endpoints",
        "analyze_http_response",
        "check_security_headers",
        "check_cors",
        "check_cookie_security",
        "check_sql_injection",
        "check_command_injection",
        "check_idor",
        "check_authentication",
        "check_sensitive_disclosure",
    ]
    TOOL_MAP: dict[str, Callable[..., str]] = {
        name: _make_json_tool_adapter(getattr(tools, name))
        for name in _RAW_TOOLS
        if hasattr(tools, name)
    }
    TOOLS_DESCRIPTION: str = """
- validate_target: Hedef URL, protokol ve kapsam doğrulaması yapar (İlk adımda çağrılmalıdır).
  Args: {"url": "<target_url>", "allowed_hosts": ["<hostname>"]}
- discover_endpoints: Hedef üzerindeki erişilebilir web/API uç noktalarını (endpoint) keşfeder.
  Args: {"base_url": "<target_url>", "allowed_hosts": ["<hostname>"], "wordlist": ["api", "admin", "login", "rest", "ftp", "metrics"]}
- analyze_http_response: Belirtilen URL'nin HTTP durum kodu, başlıkları ve yanıt davranışını analiz eder.
  Args: {"url": "<endpoint_url>", "method": "GET", "allowed_hosts": ["<hostname>"]}
- check_security_headers: Eksik veya hatalı yapılandırılmış HTTP güvenlik başlıklarını (CSP, HSTS, X-Frame-Options vb.) denetler.
  Args: {"url": "<target_url>", "allowed_hosts": ["<hostname>"]}
- check_cors: CORS yapılandırmasını ve güvensiz Origin politikalarını kontrol eder.
  Args: {"url": "<target_url>", "allowed_hosts": ["<hostname>"]}
- check_cookie_security: Çerezlerin Secure, HttpOnly ve SameSite bayraklarını inceler.
  Args: {"url": "<target_url>", "allowed_hosts": ["<hostname>"]}
- check_sql_injection: Parametreler üzerinde güvenli ve yıkıcı olmayan SQL Injection doğrulaması yapar.
  Args: {"url": "<endpoint_url>", "method": "GET", "parameters": {"id": "1"}, "allowed_hosts": ["<hostname>"]}
- check_command_injection: Parametreler üzerinde güvenli Command Injection doğrulaması yapar.
  Args: {"url": "<endpoint_url>", "method": "GET", "parameters": {"host": "127.0.0.1"}, "allowed_hosts": ["<hostname>"]}
- check_idor: Yetkilendirme ve IDOR kontrollerini test eder.
  Args: {"url": "<endpoint_url_with_{id}>", "account_a": {"id": "1", "token": ""}, "account_b": {"id": "2", "token": ""}, "allowed_hosts": ["<hostname>"]}
- check_authentication: Korunan bir uç noktada kimlik doğrulama ve JWT/Token davranışını denetler.
  Args: {"protected_url": "<endpoint_url>", "allowed_hosts": ["<hostname>"]}
- check_sensitive_disclosure: HTTP yanıt gövdesinde sızdırılmış hassas bilgileri (anahtarlar, stack trace, iç IP, e-posta) tarar.
  Args: {"url": "<endpoint_url>", "allowed_hosts": ["<hostname>"]}
""".strip()


# ---------------------------------------------------------------------------
# 1. Setup & Configuration
# ---------------------------------------------------------------------------
load_dotenv()

OPENROUTER_API_KEY: str | None = os.getenv("OPENROUTER_API_KEY")
MODEL_NAME: str = os.getenv("MODEL_NAME", "openai/gpt-4o-mini")

console = Console()

if not OPENROUTER_API_KEY:
    console.print(
        Panel(
            "[bold red]HATA:[/bold red] `OPENROUTER_API_KEY` ortam değişkeni bulunamadı.\n"
            "Lütfen `.env` dosyanıza `OPENROUTER_API_KEY=<anahtarınız>` ekleyin.",
            title="Yapılandırma Hatası",
            border_style="red",
        )
    )
    sys.exit(1)

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=OPENROUTER_API_KEY,
)


# ---------------------------------------------------------------------------
# 2. Orchestrator Agent (ReAct Loop)
# ---------------------------------------------------------------------------
def build_orchestrator_system_prompt(target_url: str) -> str:
    """Constructs the system prompt enforcing the JSON ReAct schema."""
    available_tool_names = ", ".join(TOOL_MAP.keys())
    parsed_host = urlparse(target_url).hostname or "127.0.0.1"
    return (
        "You are an autonomous Security Analysis Orchestrator Agent performing an "
        "authorized security posture and misconfiguration assessment.\n\n"
        f"TARGET URL: {target_url}\n"
        f"AUTHORIZED HOST: {parsed_host}\n\n"
        "AVAILABLE TOOLS:\n"
        f"{TOOLS_DESCRIPTION}\n"
        f"Registered tool identifiers in TOOL_MAP: [{available_tool_names}]\n\n"
        "INSTRUCTIONS:\n"
        "1. Analyze the target step-by-step using the ReAct (Reasoning + Acting) paradigm.\n"
        "2. Start by validating the target (`validate_target`), then discover endpoints and check security headers, CORS, cookies, disclosure, and relevant endpoint checks.\n"
        "3. At each step, decide which single tool to run next, or choose 'FINISH' when "
        "sufficient diagnostic information has been gathered.\n"
        f"4. Always include `\"allowed_hosts\": [\"{parsed_host}\"]` in `args` when calling tools.\n"
        "5. Avoid repeating identical tool calls with the same arguments.\n"
        "6. You MUST respond ONLY with a valid JSON object matching the exact schema below:\n\n"
        "{\n"
        '  "thought": "Detailed reasoning about the current state, previous findings, and next step",\n'
        '  "tool": "Exact tool name from TOOL_MAP or \'FINISH\'",\n'
        '  "args": {"key": "value"}\n'
        "}\n\n"
        'When setting "tool" to "FINISH", set "args" to an empty object {}.'
    )


def run_orchestrator(target_url: str, max_steps: int = 8) -> list[dict[str, Any]]:
    """
    Executes the ReAct security analysis loop up to `max_steps` iterations.

    Args:
        target_url: The URL of the target application to assess.
        max_steps: Maximum number of tool execution steps before stopping.

    Returns:
        A list of step records containing `step`, `thought`, `tool`, `args`, and `output`.
    """
    execution_history: list[dict[str, Any]] = []
    parsed_host = urlparse(target_url).hostname or "127.0.0.1"

    messages: list[dict[str, str]] = [
        {"role": "system", "content": build_orchestrator_system_prompt(target_url)},
        {
            "role": "user",
            "content": (
                f"Begin the security assessment for target: {target_url}. "
                "Output your first step in the required JSON format."
            ),
        },
    ]

    for step in range(1, max_steps + 1):
        console.rule(f"[bold cyan]Adım {step} / {max_steps}[/bold cyan]")

        # Request next decision from LLM
        try:
            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=messages,
                response_format={"type": "json_object"},
                temperature=0.2,
            )
            raw_content = response.choices[0].message.content or "{}"
        except OpenAIError as api_err:
            console.print(
                Panel(
                    f"[bold red]OpenAI / OpenRouter API Hatası:[/bold red] {api_err}",
                    title=f"Adım {step} - API Hatası",
                    border_style="red",
                )
            )
            break
        except Exception as exc:
            console.print(
                Panel(
                    f"[bold red]Beklenmeyen İstek Hatası:[/bold red] {exc}",
                    title=f"Adım {step} - Hata",
                    border_style="red",
                )
            )
            break

        # Safely parse JSON response
        try:
            decision = json.loads(raw_content)
            if not isinstance(decision, dict):
                raise ValueError("LLM yanıtı bir JSON nesnesi (dict) değil.")
        except (json.JSONDecodeError, ValueError) as parse_err:
            error_msg = (
                f"JSON ayrıştırma hatası: {parse_err}. "
                "Lütfen yalnızca belirtilen şemaya uygun geçerli bir JSON nesnesi döndür."
            )
            console.print(
                Panel(
                    f"[bold red]{error_msg}[/bold red]\n\nHam Yanıt:\n{raw_content}",
                    title=f"Adım {step} - JSON Hatası",
                    border_style="red",
                )
            )
            messages.append({"role": "assistant", "content": raw_content})
            messages.append({"role": "user", "content": f"SYSTEM ERROR: {error_msg}"})
            continue

        # Extract fields with safe fallbacks for missing keys
        thought: str = str(decision.get("thought") or "Düşünce belirtilmedi.")
        tool_name: str = str(decision.get("tool") or "").strip()
        tool_args: Any = decision.get("args")
        if not isinstance(tool_args, dict):
            tool_args = {}

        # Display 'thought' using a yellow Rich Panel
        console.print(
            Panel(
                thought,
                title=f"[bold yellow]Adım {step} - Orchestrator Düşüncesi[/bold yellow]",
                border_style="yellow",
            )
        )

        # Break loop if tool == 'FINISH'
        if tool_name.upper() == "FINISH":
            console.print(
                Panel(
                    "[bold green]Orchestrator analizi tamamladı (FINISH).[/bold green]",
                    title="Analiz Tamamlandı",
                    border_style="green",
                )
            )
            execution_history.append(
                {
                    "step": step,
                    "thought": thought,
                    "tool": "FINISH",
                    "args": tool_args,
                    "output": "Assessment completed by Orchestrator.",
                }
            )
            break

        # Ensure target URL and allowed_hosts defaults are populated if omitted by LLM
        if not any(k in tool_args for k in ("url", "target", "base_url", "protected_url")):
            if tool_name == "discover_endpoints":
                tool_args["base_url"] = target_url
            elif tool_name == "check_authentication":
                tool_args["protected_url"] = target_url
            else:
                tool_args["url"] = target_url
        if "allowed_hosts" not in tool_args and parsed_host:
            tool_args["allowed_hosts"] = [parsed_host]

        # Lookup and execute tool in TOOL_MAP
        if tool_name not in TOOL_MAP:
            observation = (
                f"HATA: '{tool_name}' adlı araç TOOL_MAP içinde bulunamadı. "
                f"Geçerli araçlar: {list(TOOL_MAP.keys())} veya 'FINISH'."
            )
        else:
            tool_callable = TOOL_MAP[tool_name]
            try:
                result = tool_callable(**tool_args)
                observation = str(result) if result is not None else "(Boş çıktı)"
            except TypeError as type_err:
                observation = (
                    f"HATA: '{tool_name}' aracı çağrılırken argüman uyuşmazlığı oluştu: {type_err}. "
                    f"Gönderilen argümanlar: {json.dumps(tool_args, ensure_ascii=False)}"
                )
            except Exception as tool_err:
                observation = (
                    f"HATA: '{tool_name}' aracı çalıştırılırken istisna oluştu: "
                    f"{type(tool_err).__name__}: {tool_err}"
                )

        # Display tool call and observation output using a blue Rich Panel
        tool_panel_content = (
            f"[bold]Araç:[/bold] `{tool_name}`\n"
            f"[bold]Argümanlar:[/bold] `{json.dumps(tool_args, ensure_ascii=False)}`\n\n"
            f"[bold]Gözlem (Çıktı):[/bold]\n{observation}"
        )
        console.print(
            Panel(
                tool_panel_content,
                title=f"[bold blue]Adım {step} - Araç Çalıştırma ve Gözlem[/bold blue]",
                border_style="blue",
            )
        )

        # Append assistant decision and user tool observation to messages for context continuity
        messages.append(
            {
                "role": "assistant",
                "content": json.dumps(
                    {"thought": thought, "tool": tool_name, "args": tool_args},
                    ensure_ascii=False,
                ),
            }
        )
        messages.append(
            {
                "role": "user",
                "content": f"Tool '{tool_name}' Observation:\n{observation}",
            }
        )

        # Append step record to execution_history
        execution_history.append(
            {
                "step": step,
                "thought": thought,
                "tool": tool_name,
                "args": tool_args,
                "output": observation,
            }
        )

    return execution_history


# ---------------------------------------------------------------------------
# 3. Reporter Agent
# ---------------------------------------------------------------------------
def run_reporter(target_url: str, history: list[dict[str, Any]]) -> str:
    """
    Generates a structured Markdown Security Assessment Report from the orchestrator's history.

    Args:
        target_url: The assessed target URL.
        history: List of step records produced by `run_orchestrator`.

    Returns:
        A formatted Markdown string containing the full security report.
    """
    serialized_history = json.dumps(history, indent=2, ensure_ascii=False)

    reporter_system_prompt = (
        "You are a Senior Application Security Reporter AI. "
        "Your task is to analyze the execution history collected by the Orchestrator Agent "
        "and produce a comprehensive, professional, and well-structured Markdown Security "
        "Assessment Report.\n\n"
        "The report MUST include the following clearly delineated sections:\n"
        "1. **Executive Summary** - High-level overview of the assessment scope, target, and overall risk posture.\n"
        "2. **Step-by-Step Analysis Chain** - Chronological walkthrough of each step executed, reasoning, tools used, and key observations.\n"
        "3. **Identified Misconfigurations / Vulnerabilities** - Detailed findings backed by evidence from the tool outputs, including severity ratings (Critical/High/Medium/Low/Info).\n"
        "4. **Remediation Recommendations** - Concrete, actionable defensive fixes and security best practices to address each finding."
    )

    reporter_user_prompt = (
        f"Target URL: {target_url}\n\n"
        "Orchestrator Execution History (JSON):\n"
        f"```json\n{serialized_history}\n```\n\n"
        "Please generate the complete Markdown Security Assessment Report."
    )

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": reporter_system_prompt},
                {"role": "user", "content": reporter_user_prompt},
            ],
            temperature=0.3,
        )
        report_content = response.choices[0].message.content
        if not report_content:
            return "# Security Assessment Report\n\n_Rapor içeriği üretilemedi (boş yanıt)._"
        return report_content
    except Exception as exc:
        return (
            "# Security Assessment Report (Hata)\n\n"
            f"Rapor oluşturulurken bir hata meydana geldi: `{type(exc).__name__}: {exc}`\n\n"
            "## Ham Çalıştırma Geçmişi\n"
            f"```json\n{serialized_history}\n```"
        )


# ---------------------------------------------------------------------------
# 4. CLI Entrypoint
# ---------------------------------------------------------------------------
def main() -> None:
    """CLI entrypoint for the Two-Stage Security Analysis AI Agent."""
    console.print(
        Panel(
            "[bold white]İki Aşamalı Güvenlik Analizi AI Ajanı (Orchestrator + Reporter)[/bold white]\n"
            f"Kullanılan Model: [cyan]{MODEL_NAME}[/cyan]\n"
            f"Yüklü Araç Sayısı: [cyan]{len(TOOL_MAP)}[/cyan]",
            title="Security Analysis AI Agent",
            border_style="cyan",
        )
    )

    default_target = os.getenv("TARGET_URL") or os.getenv("JUICESHOP_URL") or "http://127.0.0.1:3000"

    if sys.stdin.isatty():
        target_url = Prompt.ask(
            "[bold cyan]Hedef URL'yi girin[/bold cyan]",
            default=default_target,
        ).strip()
    else:
        target_url = default_target

    if not target_url:
        target_url = default_target

    console.print(f"\n[bold]Hedef:[/bold] [underline]{target_url}[/underline] üzerinde analiz başlatılıyor...\n")

    # Stage 1: Run Orchestrator
    history = run_orchestrator(target_url=target_url, max_steps=8)

    # Stage 2: Run Reporter
    console.rule("[bold green]Rapor Oluşturuluyor (Reporter AI)[/bold green]")
    report_md = run_reporter(target_url=target_url, history=history)

    # Render final report in a green Rich Panel
    console.print(
        Panel(
            Markdown(report_md),
            title="[bold green]Nihai Güvenlik Değerlendirme Raporu[/bold green]",
            border_style="green",
        )
    )

    # Save report to 'security_report.md'
    report_path = Path("security_report.md")
    try:
        report_path.write_text(report_md, encoding="utf-8")
        console.print(
            f"[bold green]✓[/bold green] Rapor başarıyla kaydedildi: [bold]{report_path.resolve()}[/bold]"
        )
    except OSError as io_err:
        console.print(
            f"[bold red]✗ Rapor dosyaya kaydedilemedi ({report_path}):[/bold red] {io_err}"
        )


if __name__ == "__main__":
    main()
