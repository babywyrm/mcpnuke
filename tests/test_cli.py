"""Tests for CLI argument parsing."""

import tempfile
from pathlib import Path

import pytest

from mcpnuke.cli import (
    parse_args,
    build_url_list,
    _load_urls_from_file,
    expand_port_range,
    PUBLIC_TARGETS_FILE,
)


def test_expand_port_range():
    """Port range should expand to URLs."""
    urls = expand_port_range("localhost:9001-9003")
    assert urls == ["http://localhost:9001", "http://localhost:9002", "http://localhost:9003"]


def test_expand_port_range_single():
    """Single port range."""
    urls = expand_port_range("host:8080-8080")
    assert urls == ["http://host:8080"]


def test_expand_port_range_invalid():
    """Invalid port range should raise."""
    with pytest.raises(ValueError, match="Invalid port range"):
        expand_port_range("invalid")


def test_load_urls_from_file():
    """Load URLs from file, skip comments and blanks."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("# comment\n")
        f.write("http://a:9001\n")
        f.write("\n")
        f.write("http://b:9002\n")
        path = Path(f.name)
    try:
        urls = _load_urls_from_file(path)
        assert urls == ["http://a:9001", "http://b:9002"]
    finally:
        path.unlink()


def test_load_urls_from_nonexistent():
    """Nonexistent file returns empty list."""
    urls = _load_urls_from_file(Path("/nonexistent/file.txt"))
    assert urls == []


def test_build_url_list_targets():
    """--targets should be used."""
    args = parse_args(["--targets", "http://a:1", "http://b:2"])
    urls = build_url_list(args)
    assert "http://a:1" in urls
    assert "http://b:2" in urls


def test_build_url_list_targets_file(tmp_path):
    """--targets-file should load URLs."""
    f = tmp_path / "urls.txt"
    f.write_text("http://x:9001\nhttp://y:9002\n")
    args = parse_args(["--targets-file", str(f)])
    urls = build_url_list(args)
    assert "http://x:9001" in urls
    assert "http://y:9002" in urls


def test_build_url_list_targets_file_nonexistent():
    """Nonexistent targets file should exit."""
    args = parse_args(["--targets-file", "/nonexistent/urls.txt"])
    with pytest.raises(SystemExit):
        build_url_list(args)


def test_build_url_list_public_targets():
    """--public-targets should load from built-in file if present."""
    args = parse_args(["--public-targets"])
    if PUBLIC_TARGETS_FILE.is_file():
        urls = build_url_list(args)
        assert len(urls) > 0
        assert all(u.startswith("http://") or u.startswith("https://") for u in urls)
    else:
        with pytest.raises(SystemExit):
            build_url_list(args)


def test_build_url_list_port_range():
    """--port-range should expand."""
    args = parse_args(["--port-range", "localhost:9001-9002"])
    urls = build_url_list(args)
    assert urls == ["http://localhost:9001", "http://localhost:9002"]


def test_build_url_list_dedupes():
    """Duplicate URLs should be deduped."""
    args = parse_args(["--targets", "http://a:1", "http://a:1"])
    urls = build_url_list(args)
    assert urls == ["http://a:1"]


def test_parse_args_auth_token():
    """--auth-token should be accepted."""
    args = parse_args(["--targets", "http://localhost:9001", "--auth-token", "ghp_xxx"])
    assert args.auth_token == "ghp_xxx"


def test_parse_args_baseline():
    """--baseline and --save-baseline should be accepted."""
    args = parse_args(["--targets", "http://localhost:9001", "--baseline", "base.json"])
    assert args.baseline == "base.json"
    assert args.save_baseline is None

    args = parse_args(["--targets", "http://localhost:9001", "--save-baseline", "new_base.json"])
    assert args.save_baseline == "new_base.json"
    assert args.baseline is None


def test_parse_args_claude_phase2_workers():
    """--claude-phase2-workers should be accepted."""
    args = parse_args(
        [
            "--targets",
            "http://localhost:9001",
            "--claude",
            "--claude-phase2-workers",
            "3",
        ]
    )
    assert args.claude is True
    assert args.claude_phase2_workers == 3


def test_parse_args_bedrock_options():
    """--bedrock options should parse cleanly with --claude."""
    args = parse_args(
        [
            "--targets",
            "http://localhost:9001",
            "--claude",
            "--bedrock",
            "--bedrock-region",
            "us-east-1",
            "--bedrock-profile",
            "security",
            "--bedrock-model",
            "anthropic.claude-3-5-sonnet-20241022-v2:0",
        ]
    )
    assert args.claude is True
    assert args.bedrock is True
    assert args.bedrock_region == "us-east-1"
    assert args.bedrock_profile == "security"
    assert args.bedrock_model == "anthropic.claude-3-5-sonnet-20241022-v2:0"


def test_parse_args_deterministic():
    """--deterministic should parse cleanly."""
    args = parse_args(
        [
            "--targets",
            "http://localhost:9001",
            "--deterministic",
        ]
    )
    assert args.deterministic is True


def test_parse_args_headers_tls_and_scope():
    args = parse_args(
        [
            "--targets",
            "http://localhost:9001",
            "--header",
            "X-Tenant: blue",
            "--header",
            "X-Request-ID: abc123",
            "--tls-verify",
            "--oidc-scope",
            "mcp.read mcp.invoke",
        ]
    )
    assert args.header == ["X-Tenant: blue", "X-Request-ID: abc123"]
    assert args.tls_verify is True
    assert args.oidc_scope == "mcp.read mcp.invoke"


def test_parse_args_dpop_introspect_and_jwks():
    args = parse_args(
        [
            "--targets",
            "http://localhost:9001",
            "--dpop-proof",
            "header.payload.signature",
            "--token-introspect-url",
            "https://auth.example/introspect",
            "--token-introspect-client-id",
            "scanner",
            "--token-introspect-client-secret",
            "secret",
            "--jwks-url",
            "https://auth.example/jwks.json",
        ]
    )
    assert args.dpop_proof == "header.payload.signature"
    assert args.token_introspect_url == "https://auth.example/introspect"
    assert args.token_introspect_client_id == "scanner"
    assert args.token_introspect_client_secret == "secret"
    assert args.jwks_url == "https://auth.example/jwks.json"
