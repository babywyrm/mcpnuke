"""Tests for the profile system."""

import json
import pytest
from pathlib import Path


class TestLoadProfile:
    def _write_profile(self, tmp_path: Path, data: dict) -> str:
        p = tmp_path / "test.json"
        p.write_text(json.dumps(data))
        return str(p)

    def test_load_valid_profile(self, tmp_path):
        from mcpnuke.profile import load_profile
        data = {
            "name": "test-target",
            "version": "1",
            "tools": [
                {
                    "name": "read_secret",
                    "lane": 2,
                    "transport": "A",
                    "threat_id": "MCP-T06",
                    "notes": "Reads raw secrets from vault",
                }
            ]
        }
        path = self._write_profile(tmp_path, data)
        profile = load_profile(path)
        assert profile.name == "test-target"
        assert len(profile.tools) == 1
        assert profile.tools[0]["name"] == "read_secret"

    def test_missing_file_raises(self):
        from mcpnuke.profile import load_profile
        with pytest.raises(FileNotFoundError):
            load_profile("/nonexistent/profile.json")

    def test_invalid_json_raises(self, tmp_path):
        from mcpnuke.profile import load_profile
        bad = tmp_path / "bad.json"
        bad.write_text("not json {{{{")
        with pytest.raises(ValueError, match="Invalid profile"):
            load_profile(str(bad))

    def test_missing_name_field_raises(self, tmp_path):
        from mcpnuke.profile import load_profile
        data = {"version": "1", "tools": []}
        path = self._write_profile(tmp_path, data)
        with pytest.raises(ValueError, match="name"):
            load_profile(path)


class TestProfileLookups:
    def _make_profile(self, tmp_path: Path) -> object:
        from mcpnuke.profile import load_profile
        data = {
            "name": "camazotz",
            "version": "1",
            "tools": [
                {"name": "relay_message", "lane": 1, "transport": "A", "threat_id": "MCP-T02"},
                {"name": "read_secret",   "lane": 2, "transport": "B", "threat_id": "MCP-T06"},
            ]
        }
        p = tmp_path / "profile.json"
        p.write_text(json.dumps(data))
        return load_profile(str(p))

    def test_lane_for_known_tool(self, tmp_path):
        from mcpnuke.profile import lane_for
        profile = self._make_profile(tmp_path)
        assert lane_for(profile, "relay_message") == 1

    def test_lane_for_unknown_tool_returns_none(self, tmp_path):
        from mcpnuke.profile import lane_for
        profile = self._make_profile(tmp_path)
        assert lane_for(profile, "nonexistent_tool") is None

    def test_transport_for_known_tool(self, tmp_path):
        from mcpnuke.profile import transport_for
        profile = self._make_profile(tmp_path)
        assert transport_for(profile, "read_secret") == "B"

    def test_threat_id_for_known_tool(self, tmp_path):
        from mcpnuke.profile import threat_id_for
        profile = self._make_profile(tmp_path)
        assert threat_id_for(profile, "read_secret") == "MCP-T06"

    def test_threat_id_for_unknown_returns_empty(self, tmp_path):
        from mcpnuke.profile import threat_id_for
        profile = self._make_profile(tmp_path)
        assert threat_id_for(profile, "nope") == ""


class TestProfileCLI:
    def test_profile_flag_parses(self, tmp_path):
        from mcpnuke.cli import parse_args
        p = tmp_path / "camazotz.json"
        p.write_text('{"name":"camazotz","version":"1","tools":[]}')
        args = parse_args(["--targets", "http://localhost:8080/mcp", "--profile", str(p)])
        assert args.profile == str(p)

    def test_profile_default_is_none(self):
        from mcpnuke.cli import parse_args
        args = parse_args(["--targets", "http://localhost:8080/mcp"])
        assert getattr(args, "profile", None) is None


class TestShippedProfiles:
    """Ensure bundled profiles load and have valid structure."""

    def _profiles_dir(self) -> Path:
        import mcpnuke
        return Path(mcpnuke.__file__).parent.parent / "profiles"

    def test_camazotz_profile_loads(self):
        from mcpnuke.profile import load_profile
        path = self._profiles_dir() / "camazotz.json"
        if not path.exists():
            pytest.skip("camazotz.json not yet written")
        profile = load_profile(str(path))
        assert profile.name == "camazotz"
        assert len(profile.tools) > 0

    def test_dvmcp_profile_loads(self):
        from mcpnuke.profile import load_profile
        path = self._profiles_dir() / "dvmcp.json"
        if not path.exists():
            pytest.skip("dvmcp.json not yet written")
        profile = load_profile(str(path))
        assert profile.name == "dvmcp"

    def test_example_profile_loads(self):
        from mcpnuke.profile import load_profile
        path = self._profiles_dir() / "example.json"
        if not path.exists():
            pytest.skip("example.json not yet written")
        profile = load_profile(str(path))
        assert profile.name is not None
