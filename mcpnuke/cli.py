"""CLI argument parsing."""

import argparse
import os
import re
import sys
from pathlib import Path

# argparse exposes no public name for the object add_argument_group returns,
# so alias the real one here rather than weakening the helpers to Any.
ArgumentGroup = argparse._ArgumentGroup

# Env var for auth token (alternative to --auth-token)
AUTH_TOKEN_ENV = "MCP_AUTH_TOKEN"

# Built-in public targets (DVMCP, demo servers — run locally)
PUBLIC_TARGETS_FILE = Path(__file__).parent / "data" / "public_targets.txt"


def _positive_int_or_zero(v: str) -> int:
    """argparse type: accept non-negative int, reject negatives."""
    val = int(v)
    if val < 0:
        raise argparse.ArgumentTypeError(f"--coverage must be >= 0, got {val}")
    return val


def expand_port_range(spec: str) -> list[str]:
    m = re.match(r"^(.+):(\d+)-(\d+)$", spec)
    if not m:
        raise ValueError(f"Invalid port range spec: {spec!r}")
    host, start, end = m.group(1), int(m.group(2)), int(m.group(3))
    if end < start:
        raise ValueError(f"End port {end} < start port {start}")
    return [f"http://{host}:{p}" for p in range(start, end + 1)]


def _add_target_arguments(group: ArgumentGroup) -> None:
    group.add_argument(
        "--targets",
        nargs="+",
        metavar="URL",
        help="One or more MCP target URLs",
    )
    group.add_argument(
        "--targets-file",
        metavar="FILE",
        help="Read target URLs from file (one per line, # comments ignored)",
    )
    group.add_argument(
        "--port-range",
        metavar="HOST:START-END",
        help="Scan a port range, e.g. localhost:9001-9010",
    )
    group.add_argument(
        "--public-targets",
        action="store_true",
        help="Use built-in public targets list (DVMCP, demo servers)",
    )


def _add_auth_arguments(group: ArgumentGroup) -> None:
    group.add_argument(
        "--auth-token",
        metavar="TOKEN",
        default=os.environ.get(AUTH_TOKEN_ENV) or None,
        help="Bearer token for authenticated MCP endpoints (JWT, PAT, etc.). "
        f"Or set {AUTH_TOKEN_ENV} env var.",
    )
    group.add_argument(
        "--header",
        action="append",
        metavar="KEY:VALUE",
        help="Extra HTTP header (repeatable). Example: --header 'X-Tenant: blue'",
    )
    group.add_argument(
        "--tls-verify",
        action="store_true",
        help="Enable TLS certificate verification for outbound HTTP calls. "
        "Default is disabled for lab/self-signed targets.",
    )
    group.add_argument(
        "--oidc-url",
        metavar="URL",
        default=os.environ.get("MCP_OIDC_URL") or None,
        help="OIDC issuer URL for token fetch (e.g. http://keycloak:8080/realms/myapp). "
        "Used with --client-id and --client-secret for automatic token acquisition.",
    )
    group.add_argument(
        "--oidc-scope",
        metavar="SCOPE",
        default=os.environ.get("MCP_OIDC_SCOPE") or None,
        help="Optional OAuth2 scope for client_credentials token requests.",
    )
    group.add_argument(
        "--client-id",
        metavar="ID",
        default=os.environ.get("MCP_CLIENT_ID") or None,
        help="OAuth2 client ID for client_credentials grant. Or set MCP_CLIENT_ID env var.",
    )
    group.add_argument(
        "--client-secret",
        metavar="SECRET",
        default=os.environ.get("MCP_CLIENT_SECRET") or None,
        help="OAuth2 client secret for client_credentials grant. Or set MCP_CLIENT_SECRET env var.",
    )
    group.add_argument(
        "--token-introspect-url",
        metavar="URL",
        default=os.environ.get("MCP_INTROSPECT_URL") or None,
        help="Optional OAuth2 token introspection endpoint URL.",
    )
    group.add_argument(
        "--token-introspect-client-id",
        metavar="ID",
        default=os.environ.get("MCP_INTROSPECT_CLIENT_ID") or None,
        help="Optional client ID for token introspection requests.",
    )
    group.add_argument(
        "--token-introspect-client-secret",
        metavar="SECRET",
        default=os.environ.get("MCP_INTROSPECT_CLIENT_SECRET") or None,
        help="Optional client secret for token introspection requests.",
    )
    group.add_argument(
        "--jwks-url",
        metavar="URL",
        default=os.environ.get("MCP_JWKS_URL") or None,
        help="Optional JWKS endpoint URL for keyset metadata checks.",
    )
    group.add_argument(
        "--dpop-proof",
        metavar="JWT",
        default=os.environ.get("MCP_DPOP_PROOF") or None,
        help="Static DPoP proof JWT header value to send as DPoP. "
        "Optional and independent from bearer auth.",
    )
    group.add_argument(
        "--jwt-max-ttl",
        type=int,
        default=int(os.environ.get("MCPNUKE_JWT_MAX_TTL", "14400")),
        metavar="SEC",
        help="Maximum acceptable JWT TTL in seconds before flagging (default: 14400 = 4h). "
        "Or set MCPNUKE_JWT_MAX_TTL env var.",
    )


def _add_scan_arguments(group: ArgumentGroup) -> None:
    group.add_argument(
        "--timeout",
        type=float,
        default=25.0,
        metavar="SEC",
        help="Per-target connection timeout (default: 25)",
    )
    group.add_argument(
        "--workers",
        type=int,
        default=4,
        metavar="N",
        help="Parallel scan workers (default: 4)",
    )
    group.add_argument(
        "--max-pages",
        type=int,
        default=20,
        metavar="N",
        help="Maximum pages to follow when enumerating tools/resources/prompts "
        "via nextCursor pagination (default: 20).",
    )
    group.add_argument(
        "--protocol-mode",
        choices=["auto", "legacy", "stateless"],
        default="auto",
        help="MCP protocol mode (default: auto). 'legacy' uses the "
        "initialize/initialized handshake; 'stateless' uses the 2026-07-28 "
        "spec with Mcp-Method/Mcp-Name headers and no session; 'auto' probes "
        "for whichever the server speaks.",
    )


def _add_stdio_arguments(group: ArgumentGroup) -> None:
    group.add_argument(
        "--stdio",
        metavar="CMD",
        help="Scan a local MCP server via stdin/stdout JSON-RPC. "
        "Launch CMD as a subprocess and communicate over stdio. "
        "E.g. --stdio 'npx -y @modelcontextprotocol/server-everything'",
    )


def _add_safety_arguments(group: ArgumentGroup) -> None:
    group.add_argument(
        "--no-invoke",
        action="store_true",
        help="Static-only mode: skip all behavioral probes that call tools. "
        "Safe for production servers where tool invocation could have side effects.",
    )
    group.add_argument(
        "--safe-mode",
        action="store_true",
        help="Skip invoking tools classified as dangerous (delete, send, exec, write). "
        "Behavioral probes still run on read-only / low-risk tools.",
    )
    group.add_argument(
        "--probe-calls",
        type=int,
        default=10,
        metavar="N",
        help="Number of tool invocations per tool for deep rug pull detection (default: 10)",
    )


def _add_performance_arguments(group: ArgumentGroup) -> None:
    group.add_argument(
        "--fast",
        action="store_true",
        # The probe list must name exactly mcpnuke.checks.FAST_SKIP_CHECKS.
        # Generating docs/cli-reference.md from this parser proves the document
        # matches --help; it does not prove --help matches behaviour, which is
        # how this list sat one probe behind the code. Guarded by
        # tests/test_docs_current.py::TestFastSkipHelp.
        help="Fast scan: sample top 5 security-relevant tools, skip heavy "
        "probes (input_sanitization, error_leakage, temporal_consistency, "
        "ssrf_probe, sdk_cache_poisoning), cap probe workers at 2. Cuts "
        "LLM-backed scan time from ~30min to ~2min. Alias for --coverage 5.",
    )
    group.add_argument(
        "--coverage",
        type=lambda v: _positive_int_or_zero(v),
        default=None,
        metavar="N",
        help="Sample the top N most security-relevant tools (by keyword risk "
             "score). 0 = scan all tools. --fast is an alias for --coverage 5. "
             "Example: --coverage 20 scans ~20%% of a 100-tool server in fast-mode time.",
    )
    group.add_argument(
        "--probe-workers",
        type=int,
        default=1,
        metavar="N",
        help="Parallel deep behavioral probe threads (default: 1). "
        "Higher values speed up deep probes but increase server load.",
    )
    group.add_argument(
        "--deterministic",
        action="store_true",
        help="Deterministic scan mode: enforce stable tool ordering and single-threaded "
        "AI Phase 2/probe execution for more repeatable benchmarking.",
    )


def _add_ai_arguments(group: ArgumentGroup) -> None:
    group.add_argument(
        "--claude",
        action="store_true",
        help="Enable AI-powered analysis using Claude. Requires ANTHROPIC_API_KEY env var. "
        "Layers LLM reasoning on top of deterministic checks to catch subtle issues.",
    )
    group.add_argument(
        "--claude-max-tools",
        type=int,
        default=10,
        metavar="N",
        help="Max tools for Claude AI response analysis (default: 10). "
        "Higher = more thorough but slower and costs more.",
    )
    group.add_argument(
        "--claude-model",
        metavar="MODEL",
        default="claude-sonnet-4-20250514",
        help="Claude model to use for AI analysis (default: claude-sonnet-4-20250514). "
        "Use claude-opus-4-20250514 for deepest analysis.",
    )
    group.add_argument(
        "--claude-phase2-workers",
        type=int,
        default=1,
        metavar="N",
        help="Parallel Claude workers for Phase 2 response analysis (default: 1). "
        "Use 2-4 to reduce wall time on fast targets.",
    )
    group.add_argument(
        "--bedrock",
        action="store_true",
        help="Use AWS Bedrock runtime for Claude API calls instead of direct Anthropic API. "
        "Requires boto3 and AWS credentials.",
    )
    group.add_argument(
        "--bedrock-model",
        metavar="MODEL_ID",
        default="anthropic.claude-3-5-sonnet-20241022-v2:0",
        help="Bedrock model ID to invoke when --bedrock is enabled "
        "(default: anthropic.claude-3-5-sonnet-20241022-v2:0).",
    )
    group.add_argument(
        "--bedrock-profile",
        metavar="PROFILE",
        default=None,
        help="AWS profile name for Bedrock credentials resolution.",
    )
    group.add_argument(
        "--bedrock-region",
        metavar="REGION",
        default=None,
        help="AWS region for Bedrock Runtime (e.g. us-east-1). "
        "Defaults to AWS_REGION/AWS_DEFAULT_REGION if unset.",
    )
    group.add_argument(
        "--ollama-analysis",
        metavar="URL",
        default=None,
        help="Use a local/networked Ollama instance as the AI analysis backend instead of "
        "Claude. No API key required. Example: --ollama-analysis http://<ollama-host>:11434. "
        "Enables the same 3-phase analysis (tool schemas, responses, chain reasoning) "
        "at zero cloud cost. Compare results with --claude to benchmark local vs cloud quality.",
    )
    group.add_argument(
        "--ollama-ensemble",
        metavar="MODELS",
        default=None,
        help="Run AI analysis with multiple Ollama models and surface consensus findings. "
        "Comma-separated model list, e.g. --ollama-ensemble qwen2.5:14b,qwen2.5:7b,qwen3:4b. "
        "Requires --ollama-analysis. Findings where 2+ models independently flag the same "
        "taxonomy ID are tagged [CONSENSUS Nx] (high confidence); single-model findings "
        "are tagged [CANDIDATE]. Use this to validate AI findings without relying on one model.",
    )
    group.add_argument(
        "--ollama-model",
        metavar="MODEL",
        default="qwen2.5:14b",
        help="Ollama model to use when --ollama-analysis is set (default: qwen2.5:14b). "
        "Larger models produce more thorough analysis; smaller models are faster.",
    )


def _add_tool_server_arguments(group: ArgumentGroup) -> None:
    group.add_argument(
        "--tool-names-file",
        metavar="FILE",
        help="Custom wordlist of tool names for ToolServer enumeration "
        "(one per line, # comments). Supplements the built-in list.",
    )


def _add_output_arguments(group: ArgumentGroup) -> None:
    group.add_argument(
        "--json",
        metavar="FILE",
        dest="json_out",
        help="Write JSON report to FILE",
    )
    group.add_argument(
        "--sarif",
        metavar="FILE",
        dest="sarif_out",
        help="Write SARIF 2.1.0 report to FILE (for GitHub Code Scanning, VS Code, and CI integration)",
    )
    group.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )
    group.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output (very noisy)",
    )
    group.add_argument(
        "--no-color",
        action="store_true",
        default=bool(os.environ.get("NO_COLOR")),
        help="Disable colored output. Respects the NO_COLOR env var (https://no-color.org).",
    )
    group.add_argument(
        "--group-findings",
        action="store_true",
        help="Collapse similar findings by check/severity into compact rows "
        "with affected-tool lists and counts.",
    )
    group.add_argument(
        "--fail-on",
        metavar="SEVERITY",
        default="high",
        choices=["critical", "high", "medium", "low", "any", "none"],
        help="Exit 1 when findings at or above this severity are found. "
             "Choices: critical, high (default), medium, low, any, none. "
             "'none' always exits 0 (useful in CI for informational scans).",
    )


def _add_policy_arguments(group: ArgumentGroup) -> None:
    group.add_argument(
        "--generate-policy",
        metavar="FILE",
        dest="policy_out",
        help="Generate nullfield policy YAML from findings and write to FILE",
    )
    group.add_argument(
        "--policy-name",
        metavar="NAME",
        default="mcpnuke-recommended",
        help="metadata.name for the generated NullfieldPolicy",
    )
    group.add_argument(
        "--policy-namespace",
        metavar="NAMESPACE",
        default="",
        help="metadata.namespace for the generated NullfieldPolicy",
    )
    group.add_argument(
        "--policy-labels",
        metavar="KEY=VALUE",
        action="append",
        default=[],
        help="metadata.labels entry, repeatable. "
        "Example: --policy-labels nullfield.io/lane=machine",
    )
    group.add_argument(
        "--policy-selector",
        metavar="KEY=VALUE",
        action="append",
        default=[],
        help="spec.selector.matchLabels entry, repeatable. Without it, "
        "the selector matches every pod, which is typically too broad. "
        "Example: --policy-selector app=brain-gateway",
    )


def _add_lane_arguments(group: ArgumentGroup) -> None:
    group.add_argument(
        "--by-lane",
        action="store_true",
        help="Group scan findings by agentic-identity lane (1..5) and print "
        "a per-lane severity tally. Also emitted to --json when both are set.",
    )
    group.add_argument(
        "--coverage-report",
        metavar="CAMAZOTZ_URL",
        help="Fetch camazotz /api/lanes (schema v1) from CAMAZOTZ_URL, "
        "intersect with this scan's findings, and print a cross-project "
        "coverage report. Example: --coverage-report http://localhost:3000",
    )
    group.add_argument(
        "--taxonomy",
        metavar="PATH_OR_URL",
        default=None,
        help="Override the vendored agentic-sec threat taxonomy "
        "(mcpnuke/data/taxonomy/lanes.yaml). Accepts a filesystem path or "
        "http(s) URL. Used to validate finding threat_ids and to surface "
        "lane/transport metadata. The vendored copy is used when not set.",
    )
    group.add_argument(
        "--profile",
        metavar="FILE",
        default=None,
        help="Path to a target profile JSON (maps tool names to lane, transport, "
             "threat ID, and notes). Enriches AI prompts and finding attribution. "
             "Bundled profiles: profiles/camazotz.json, profiles/dvmcp.json.",
    )


def _add_differential_arguments(group: ArgumentGroup) -> None:
    group.add_argument(
        "--baseline",
        metavar="FILE",
        help="Compare against baseline (differential scan)",
    )
    group.add_argument(
        "--diff-baseline",
        metavar="FILE",
        default=None,
        help="Path to a previous mcpnuke JSON output to diff against. "
             "The scan result will include a 'diff' block showing new, "
             "resolved, and severity-changed findings.",
    )
    group.add_argument(
        "--save-baseline",
        metavar="FILE",
        help="Save current scan as baseline for future differential scans",
    )


def _add_inference_arguments(group: ArgumentGroup) -> None:
    group.add_argument(
        "--inference",
        action="store_true",
        help="Enable inference backend scanning — auto-detect LLM backends "
        "(Ollama, vLLM, LocalAI, llama.cpp, TGI) from MCP server context "
        "and probe for unauthenticated access. Off by default.",
    )
    group.add_argument(
        "--inference-host",
        metavar="URL",
        default=None,
        help="Explicit inference backend URL to probe (e.g. http://gpu-box:11434). "
        "Implies --inference. Supports Ollama, vLLM, LocalAI, llama.cpp, and TGI.",
    )
    group.add_argument(
        "--inference-baseline",
        metavar="FILE",
        default=None,
        help="Path to a model integrity manifest (JSON). Compares current model "
        "digests against this baseline to detect tampering, removal, or injection. "
        "Generate with --save-inference-baseline.",
    )
    group.add_argument(
        "--save-inference-baseline",
        metavar="FILE",
        default=None,
        help="Snapshot current model state to FILE as a known-good baseline. "
        "Use with --inference-host to capture digests for later integrity checks.",
    )


def _add_k8s_arguments(group: ArgumentGroup) -> None:
    group.add_argument(
        "--k8s-api-url",
        metavar="URL",
        default=os.environ.get("MCPNUKE_K8S_API_URL") or None,
        help="Kubernetes API server URL for external scanning (e.g. http://localhost:8001 "
        "for kubectl proxy). Or set MCPNUKE_K8S_API_URL env var.",
    )
    group.add_argument(
        "--k8s-discover",
        action="store_true",
        help="Auto-discover MCP targets via K8s service discovery "
        "(requires running inside a pod with service list permissions)",
    )
    group.add_argument(
        "--k8s-discover-namespaces",
        nargs="+",
        metavar="NS",
        help="Namespaces to scan for MCP services (default: current namespace). "
        "Use with --k8s-discover.",
    )
    group.add_argument(
        "--k8s-discover-only",
        action="store_true",
        help="Run K8s discovery and print endpoint list only; skip MCP scanning. Use with --json to export URLs.",
    )
    group.add_argument(
        "--k8s-discovery-workers",
        type=int,
        default=10,
        metavar="N",
        help="Concurrent probes during K8s MCP discovery (default: 10). Use higher for clusters with many services.",
    )
    group.add_argument(
        "--k8s-max-endpoints",
        type=int,
        default=None,
        metavar="N",
        help="Cap number of MCP endpoints to scan (default: no limit). Useful for large clusters.",
    )
    group.add_argument(
        "--k8s-namespace",
        metavar="NS",
        default="default",
        help="Kubernetes namespace for internal checks (default: default)",
    )
    group.add_argument(
        "--k8s-no-probe",
        action="store_true",
        help="Skip active probing during K8s discovery (use port matching only)",
    )
    group.add_argument(
        "--k8s-token",
        metavar="TOKEN",
        default=os.environ.get("MCPNUKE_K8S_TOKEN") or None,
        help="K8s bearer token for external API access. "
        "Or set MCPNUKE_K8S_TOKEN env var. "
        "Prefer --k8s-token-file to avoid ps(1) exposure.",
    )
    group.add_argument(
        "--k8s-token-file",
        metavar="FILE",
        default=None,
        help="Read K8s bearer token from FILE (avoids ps aux exposure).",
    )
    group.add_argument(
        "--no-k8s",
        action="store_true",
        help="Skip Kubernetes internal checks",
    )


def _add_diagnostics_arguments(group: ArgumentGroup) -> None:
    group.add_argument(
        "--doctor",
        action="store_true",
        help="Check installation health: core deps, optional extras, env vars, connectivity.",
    )


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI parser.

    Split out from parse_args so documentation generation can introspect the
    parser without consuming argv. Groups are declared in the order --help
    prints them, and every flag belongs to exactly one.
    """
    p = argparse.ArgumentParser(
        prog="mcpnuke",
        # argparse does not group the usage line, so the generated one lists all
        # 76 flags and pushes the first group heading 31 lines down.
        usage="mcpnuke [--targets URL ...] [options]",
        description="mcpnuke — MCP Red Teaming & Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_target_arguments(p.add_argument_group("Target Selection"))
    _add_auth_arguments(p.add_argument_group("Authentication"))
    _add_scan_arguments(p.add_argument_group("Scan Options"))
    _add_stdio_arguments(p.add_argument_group("Stdio Transport"))
    _add_safety_arguments(p.add_argument_group("Safety Controls"))
    _add_performance_arguments(p.add_argument_group("Performance"))
    _add_ai_arguments(p.add_argument_group("AI Analysis"))
    _add_tool_server_arguments(p.add_argument_group("Tool Server"))
    _add_output_arguments(p.add_argument_group("Output"))
    _add_policy_arguments(p.add_argument_group("Policy Generation"))
    _add_lane_arguments(p.add_argument_group("Lane Reporting & Cross-Project Coverage"))
    _add_differential_arguments(p.add_argument_group("Differential"))
    _add_inference_arguments(p.add_argument_group("Inference Backend"))
    _add_k8s_arguments(p.add_argument_group("Kubernetes"))
    _add_diagnostics_arguments(p.add_argument_group("Diagnostics"))
    return p


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    return build_parser().parse_args(args)


def _load_urls_from_file(path: Path) -> list[str]:
    """Load URLs from file, one per line, skip comments and blanks."""
    if not path.is_file():
        return []
    urls = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            urls.append(line)
    return urls


def build_url_list(args: argparse.Namespace) -> list[str]:
    urls: list[str] = []

    if args.targets:
        urls.extend(args.targets)

    if args.targets_file:
        p = Path(args.targets_file)
        if not p.is_file():
            print(f"Error: targets file not found: {p}", file=sys.stderr)
            sys.exit(1)
        urls.extend(_load_urls_from_file(p))

    if args.public_targets and PUBLIC_TARGETS_FILE.is_file():
        urls.extend(_load_urls_from_file(PUBLIC_TARGETS_FILE))

    if args.port_range:
        try:
            urls.extend(expand_port_range(args.port_range))
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    if not urls:
        print(
            "Error: specify --targets, --port-range, --targets-file, or --public-targets",
            file=sys.stderr,
        )
        sys.exit(1)

    seen: set[str] = set()
    deduped: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped
