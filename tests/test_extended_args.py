"""Tests for Phase 2 Tier 1 extended argument heuristics."""

from mcpnuke.checks.tool_probes import _build_extended_args, _build_safe_args


class TestBuildSafeArgsBaseline:
    """Existing _build_safe_args behavior must not regress."""

    def test_required_string_filled(self):
        tool = {
            "name": "read_file",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            }
        }
        args = _build_safe_args(tool)
        assert "path" in args

    def test_optional_param_not_filled_by_safe_args(self):
        tool = {
            "name": "search",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer"},
                },
                "required": ["query"],
            }
        }
        args = _build_safe_args(tool)
        assert "query" in args
        assert "limit" not in args


class TestBuildExtendedArgs:
    """_build_extended_args fills optional params with interesting heuristic values."""

    def test_optional_string_filled(self):
        tool = {
            "name": "search",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "filter": {"type": "string"},
                },
                "required": ["query"],
            }
        }
        args = _build_extended_args(tool)
        assert "query" in args
        assert "filter" in args

    def test_optional_integer_filled(self):
        tool = {
            "name": "list_items",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer"},
                },
                "required": [],
            }
        }
        args = _build_extended_args(tool)
        assert "limit" in args
        assert isinstance(args["limit"], int)

    def test_optional_boolean_filled(self):
        tool = {
            "name": "get_config",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "verbose": {"type": "boolean"},
                },
                "required": [],
            }
        }
        args = _build_extended_args(tool)
        assert "verbose" in args
        assert isinstance(args["verbose"], bool)

    def test_enum_uses_first_value(self):
        tool = {
            "name": "do_action",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "mode": {"type": "string", "enum": ["read", "write", "admin"]},
                },
                "required": [],
            }
        }
        args = _build_extended_args(tool)
        assert args.get("mode") == "read"

    def test_path_param_gets_traversal_probe(self):
        """Optional path params should get a directory-traversal probe value."""
        tool = {
            "name": "read_file",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"},
                },
                "required": [],
            }
        }
        args = _build_extended_args(tool)
        assert "file_path" in args
        val = str(args["file_path"])
        assert "/" in val or ".." in val

    def test_url_param_gets_ssrf_probe(self):
        """Optional url/endpoint params should get a loopback SSRF probe value."""
        tool = {
            "name": "fetch_data",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "endpoint_url": {"type": "string"},
                },
                "required": [],
            }
        }
        args = _build_extended_args(tool)
        assert "endpoint_url" in args
        val = str(args["endpoint_url"])
        assert val.startswith("http") or "localhost" in val or "169.254" in val

    def test_no_schema_returns_empty(self):
        tool = {"name": "bare_tool"}
        args = _build_extended_args(tool)
        assert isinstance(args, dict)

    def test_required_params_still_included(self):
        tool = {
            "name": "create",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "description": {"type": "string"},
                },
                "required": ["name"],
            }
        }
        args = _build_extended_args(tool)
        assert "name" in args
        assert "description" in args
