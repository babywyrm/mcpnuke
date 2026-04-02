"""CLI argument parsing."""

import argparse
import os
import re
import sys
from pathlib import Path

# Env var for auth token (alternative to --auth-token)
AUTH_TOKEN_ENV = "MCP_AUTH_TOKEN"

# Built-in public targets (DVMCP, demo servers — run locally)
PUBLIC_TARGETS_FILE = Path(__file__).parent / "data" / "public_targets.txt"


def expand_port_range(spec: str) -> list[str]:
    m = re.match(r"^(.+):(\d+)-(\d+)$", spec)
    if not m:
        raise ValueError(f"Invalid port range spec: {spec!r}")
    host, start, end = m.group(1), int(m.group(2)), int(m.group(3))
    if end < start:
        raise ValueError(f"End port {end} < start port {start}")
    return [f"http://{host}:{p}" for p in range(start, end + 1)]


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="mcpnuke — MCP Red Teaming & Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--targets",
        nargs="+",
        metavar="URL",
        help="One or more MCP target URLs",
    )
    p.add_argument(
        "--port-range",
        metavar="HOST:START-END",
        help="Scan a port range, e.g. localhost:9001-9010",
    )
    p.add_argument(
        "--targets-file",
        metavar="FILE",
        help="Read target URLs from file (one per line, # comments ignored)",
    )
    p.add_argument(
        "--public-targets",
        action="store_true",
        help="Use built-in public targets list (DVMCP, demo servers)",
    )
    p.add_argument(
        "--auth-token",
        metavar="TOKEN",
        default=os.environ.get(AUTH_TOKEN_ENV) or None,
        help="Bearer token for authenticated MCP endpoints (JWT, PAT, etc.). "
        f"Or set {AUTH_TOKEN_ENV} env var.",
    )
    p.add_argument(
        "--oidc-url",
        metavar="URL",
        default=os.environ.get("MCP_OIDC_URL") or None,
        help="OIDC issuer URL for token fetch (e.g. http://keycloak:8080/realms/myapp). "
        "Used with --client-id and --client-secret for automatic token acquisition.",
    )
    p.add_argument(
        "--client-id",
        metavar="ID",
        default=os.environ.get("MCP_CLIENT_ID") or None,
        help="OAuth2 client ID for client_credentials grant. Or set MCP_CLIENT_ID env var.",
    )
    p.add_argument(
        "--client-secret",
        metavar="SECRET",
        default=os.environ.get("MCP_CLIENT_SECRET") or None,
        help="OAuth2 client secret for client_credentials grant. Or set MCP_CLIENT_SECRET env var.",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=25.0,
        metavar="SEC",
        help="Per-target connection timeout (default: 25)",
    )
    p.add_argument(
        "--workers",
        type=int,
        default=4,
        metavar="N",
        help="Parallel scan workers (default: 4)",
    )
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )
    p.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output (very noisy)",
    )
    p.add_argument(
        "--json",
        metavar="FILE",
        dest="json_out",
        help="Write JSON report to FILE",
    )
    p.add_argument(
        "--baseline",
        metavar="FILE",
        help="Compare against baseline (differential scan)",
    )
    p.add_argument(
        "--save-baseline",
        metavar="FILE",
        help="Save current scan as baseline for future differential scans",
    )
    p.add_argument(
        "--no-invoke",
        action="store_true",
        help="Static-only mode: skip all behavioral probes that call tools. "
        "Safe for production servers where tool invocation could have side effects.",
    )
    p.add_argument(
        "--safe-mode",
        action="store_true",
        help="Skip invoking tools classified as dangerous (delete, send, exec, write). "
        "Behavioral probes still run on read-only / low-risk tools.",
    )
    p.add_argument(
        "--probe-calls",
        type=int,
        default=10,
        metavar="N",
        help="Number of tool invocations per tool for deep rug pull detection (default: 10)",
    )
    p.add_argument(
        "--k8s-namespace",
        metavar="NS",
        default="default",
        help="Kubernetes namespace for internal checks (default: default)",
    )
    p.add_argument(
        "--no-k8s",
        action="store_true",
        help="Skip Kubernetes internal checks",
    )
    p.add_argument(
        "--k8s-discover",
        action="store_true",
        help="Auto-discover MCP targets via K8s service discovery "
        "(requires running inside a pod with service list permissions)",
    )
    p.add_argument(
        "--k8s-discover-namespaces",
        nargs="+",
        metavar="NS",
        help="Namespaces to scan for MCP services (default: current namespace). "
        "Use with --k8s-discover.",
    )
    p.add_argument(
        "--k8s-no-probe",
        action="store_true",
        help="Skip active probing during K8s discovery (use port matching only)",
    )
    p.add_argument(
        "--k8s-discovery-workers",
        type=int,
        default=10,
        metavar="N",
        help="Concurrent probes during K8s MCP discovery (default: 10). Use higher for clusters with many services.",
    )
    p.add_argument(
        "--k8s-max-endpoints",
        type=int,
        default=None,
        metavar="N",
        help="Cap number of MCP endpoints to scan (default: no limit). Useful for large clusters.",
    )
    p.add_argument(
        "--k8s-discover-only",
        action="store_true",
        help="Run K8s discovery and print endpoint list only; skip MCP scanning. Use with --json to export URLs.",
    )
    p.add_argument(
        "--tool-names-file",
        metavar="FILE",
        help="Custom wordlist of tool names for ToolServer enumeration "
        "(one per line, # comments). Supplements the built-in list.",
    )
    p.add_argument(
        "--stdio",
        metavar="CMD",
        help="Scan a local MCP server via stdin/stdout JSON-RPC. "
        "Launch CMD as a subprocess and communicate over stdio. "
        "E.g. --stdio 'npx -y @modelcontextprotocol/server-everything'",
    )
    p.add_argument(
        "--fast",
        action="store_true",
        help="Fast scan: sample top 5 security-relevant tools, skip heavy "
        "probes (input_sanitization, error_leakage, temporal_consistency, "
        "ssrf_probe), cap probe workers at 2. Cuts LLM-backed scan time "
        "from ~30min to ~2min.",
    )
    p.add_argument(
        "--group-findings",
        action="store_true",
        help="Collapse similar findings by check/severity into compact rows "
        "with affected-tool lists and counts.",
    )
    p.add_argument(
        "--probe-workers",
        type=int,
        default=1,
        metavar="N",
        help="Parallel deep behavioral probe threads (default: 1). "
        "Higher values speed up deep probes but increase server load.",
    )
    p.add_argument(
        "--deterministic",
        action="store_true",
        help="Deterministic scan mode: enforce stable tool ordering and single-threaded "
        "AI Phase 2/probe execution for more repeatable benchmarking.",
    )
    p.add_argument(
        "--claude-max-tools",
        type=int,
        default=10,
        metavar="N",
        help="Max tools for Claude AI response analysis (default: 10). "
        "Higher = more thorough but slower and costs more.",
    )
    p.add_argument(
        "--claude-phase2-workers",
        type=int,
        default=1,
        metavar="N",
        help="Parallel Claude workers for Phase 2 response analysis (default: 1). "
        "Use 2-4 to reduce wall time on fast targets.",
    )
    p.add_argument(
        "--claude",
        action="store_true",
        help="Enable AI-powered analysis using Claude. Requires ANTHROPIC_API_KEY env var. "
        "Layers LLM reasoning on top of deterministic checks to catch subtle issues.",
    )
    p.add_argument(
        "--bedrock",
        action="store_true",
        help="Use AWS Bedrock runtime for Claude API calls instead of direct Anthropic API. "
        "Requires boto3 and AWS credentials.",
    )
    p.add_argument(
        "--bedrock-region",
        metavar="REGION",
        default=None,
        help="AWS region for Bedrock Runtime (e.g. us-east-1). "
        "Defaults to AWS_REGION/AWS_DEFAULT_REGION if unset.",
    )
    p.add_argument(
        "--bedrock-profile",
        metavar="PROFILE",
        default=None,
        help="AWS profile name for Bedrock credentials resolution.",
    )
    p.add_argument(
        "--bedrock-model",
        metavar="MODEL_ID",
        default="anthropic.claude-3-5-sonnet-20241022-v2:0",
        help="Bedrock model ID to invoke when --bedrock is enabled "
        "(default: anthropic.claude-3-5-sonnet-20241022-v2:0).",
    )
    p.add_argument(
        "--claude-model",
        metavar="MODEL",
        default="claude-sonnet-4-20250514",
        help="Claude model to use for AI analysis (default: claude-sonnet-4-20250514). "
        "Use claude-opus-4-20250514 for deepest analysis.",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        default=bool(os.environ.get("NO_COLOR")),
        help="Disable colored output. Respects the NO_COLOR env var (https://no-color.org).",
    )
    p.add_argument(
        "--doctor",
        action="store_true",
        help="Check installation health: core deps, optional extras, env vars, connectivity.",
    )
    return p.parse_args(args)


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
