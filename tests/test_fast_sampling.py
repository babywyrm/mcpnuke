"""Tests for fast-mode tool security scoring and sampling."""

import pytest

from mcpnuke.checks import _tool_security_score, _pick_security_relevant


# ---------------------------------------------------------------------------
# Fixture: realistic MCP tool definitions from Artifice scan
# ---------------------------------------------------------------------------

TOOL_SERVER_CONFIG: dict = {
    "name": "server-config",
    "description": "Show current Minecraft server configuration and service status",
    "inputSchema": {"type": "object", "properties": {}},
}

TOOL_FETCH_SKIN: dict = {
    "name": "fetch-skin",
    "description": "Fetch a Minecraft player skin from a URL for display",
    "inputSchema": {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "URL to the player skin"},
            "player": {"type": "string", "description": "Player name"},
        },
    },
}

TOOL_ADMIN_WEBHOOK: dict = {
    "name": "admin-webhook",
    "description": "Register a webhook URL to receive server event notifications",
    "inputSchema": {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "label": {"type": "string"},
        },
    },
}

TOOL_RUN_MAINTENANCE: dict = {
    "name": "run-maintenance",
    "description": "Run a server maintenance command. Restricted to safe operations only.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "command": {"type": "string"},
        },
    },
}

TOOL_SMELT_ITEM: dict = {
    "name": "smelt-item",
    "description": "Smelt items using a furnace-like block",
    "inputSchema": {
        "type": "object",
        "properties": {
            "x": {"type": "number"},
            "y": {"type": "number"},
            "z": {"type": "number"},
            "inputItem": {"type": "string"},
            "fuelItem": {"type": "string"},
        },
    },
}

TOOL_MOVE_TO_POSITION: dict = {
    "name": "move-to-position",
    "description": "Move the bot to a specific position",
    "inputSchema": {
        "type": "object",
        "properties": {
            "x": {"type": "number"},
            "y": {"type": "number"},
            "z": {"type": "number"},
        },
    },
}

TOOL_LIST_INVENTORY: dict = {
    "name": "list-inventory",
    "description": "List all items in the bot's inventory",
    "inputSchema": {"type": "object", "properties": {}},
}

TOOL_SECRETS_LEAK_CONFIG: dict = {
    "name": "secrets.leak_config",
    "description": "Return internal configuration including sensitive values",
    "inputSchema": {
        "type": "object",
        "properties": {
            "filter": {"type": "string"},
            "reason": {"type": "string"},
        },
    },
}

TOOL_HIDDEN_EXEC: dict = {
    "name": "tool.hidden_exec",
    "description": "Execute a hidden system command",
    "inputSchema": {
        "type": "object",
        "properties": {
            "command": {"type": "string"},
        },
    },
}

TOOL_BACKUP_WORLD: dict = {
    "name": "backup-world",
    "description": "Create a backup of the current Minecraft world",
    "inputSchema": {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
        },
    },
}


# ---------------------------------------------------------------------------
# Score ordering tests
# ---------------------------------------------------------------------------

class TestToolSecurityScore:
    """Verify that the scoring function ranks tools by actual threat level."""

    def test_server_config_outranks_smelt_item(self):
        assert _tool_security_score(TOOL_SERVER_CONFIG) > _tool_security_score(TOOL_SMELT_ITEM)

    def test_server_config_outranks_move_to_position(self):
        assert _tool_security_score(TOOL_SERVER_CONFIG) > _tool_security_score(TOOL_MOVE_TO_POSITION)

    def test_run_maintenance_outranks_smelt_item(self):
        assert _tool_security_score(TOOL_RUN_MAINTENANCE) > _tool_security_score(TOOL_SMELT_ITEM)

    def test_admin_webhook_outranks_list_inventory(self):
        assert _tool_security_score(TOOL_ADMIN_WEBHOOK) > _tool_security_score(TOOL_LIST_INVENTORY)

    def test_fetch_skin_outranks_move_to_position(self):
        assert _tool_security_score(TOOL_FETCH_SKIN) > _tool_security_score(TOOL_MOVE_TO_POSITION)

    def test_hidden_exec_is_highest(self):
        """Tool with 'exec' in name + 'command' param should dominate."""
        all_tools = [
            TOOL_SERVER_CONFIG, TOOL_FETCH_SKIN, TOOL_ADMIN_WEBHOOK,
            TOOL_RUN_MAINTENANCE, TOOL_SMELT_ITEM, TOOL_MOVE_TO_POSITION,
        ]
        exec_score = _tool_security_score(TOOL_HIDDEN_EXEC)
        assert all(exec_score >= _tool_security_score(t) for t in all_tools)

    def test_secrets_leak_outranks_generic_tools(self):
        assert _tool_security_score(TOOL_SECRETS_LEAK_CONFIG) > _tool_security_score(TOOL_SMELT_ITEM)
        assert _tool_security_score(TOOL_SECRETS_LEAK_CONFIG) > _tool_security_score(TOOL_MOVE_TO_POSITION)
        assert _tool_security_score(TOOL_SECRETS_LEAK_CONFIG) > _tool_security_score(TOOL_LIST_INVENTORY)

    def test_benign_tools_score_low(self):
        for tool in [TOOL_SMELT_ITEM, TOOL_MOVE_TO_POSITION, TOOL_LIST_INVENTORY]:
            assert _tool_security_score(tool) < 10, (
                f"{tool['name']} scored {_tool_security_score(tool)}, expected < 10"
            )

    def test_high_value_floor_applies(self):
        """Zero-param config tool must hit the floor score."""
        score = _tool_security_score(TOOL_SERVER_CONFIG)
        assert score >= 15, f"server-config scored {score}, expected >= 15 (floor)"


# ---------------------------------------------------------------------------
# Sampling tests
# ---------------------------------------------------------------------------

class TestPickSecurityRelevant:
    """Verify that fast-mode sampling selects the right tools."""

    ARTIFICE_TOOLS: list[dict] = [
        TOOL_SERVER_CONFIG,
        TOOL_FETCH_SKIN,
        TOOL_ADMIN_WEBHOOK,
        TOOL_RUN_MAINTENANCE,
        TOOL_BACKUP_WORLD,
        TOOL_SMELT_ITEM,
        TOOL_MOVE_TO_POSITION,
        TOOL_LIST_INVENTORY,
    ]

    def test_top5_includes_server_config(self):
        """The bug: server-config was excluded from fast-mode top 5."""
        top5 = _pick_security_relevant(self.ARTIFICE_TOOLS, 5)
        names = {t["name"] for t in top5}
        assert "server-config" in names, f"server-config missing from top 5: {names}"

    def test_top5_includes_run_maintenance(self):
        top5 = _pick_security_relevant(self.ARTIFICE_TOOLS, 5)
        names = {t["name"] for t in top5}
        assert "run-maintenance" in names

    def test_top5_includes_admin_webhook(self):
        top5 = _pick_security_relevant(self.ARTIFICE_TOOLS, 5)
        names = {t["name"] for t in top5}
        assert "admin-webhook" in names

    def test_top5_includes_fetch_skin(self):
        top5 = _pick_security_relevant(self.ARTIFICE_TOOLS, 5)
        names = {t["name"] for t in top5}
        assert "fetch-skin" in names

    def test_top5_excludes_benign_tools(self):
        """smelt-item and move-to-position should not appear in top 5."""
        top5 = _pick_security_relevant(self.ARTIFICE_TOOLS, 5)
        names = {t["name"] for t in top5}
        assert "smelt-item" not in names, f"smelt-item should not be in top 5: {names}"
        assert "move-to-position" not in names, f"move-to-position should not be in top 5: {names}"

    def test_camazotz_tools_rank_correctly(self):
        """secrets.leak_config and hidden_exec should rank in top 5."""
        camazotz_tools = [
            TOOL_SECRETS_LEAK_CONFIG,
            TOOL_HIDDEN_EXEC,
            TOOL_FETCH_SKIN,
            TOOL_ADMIN_WEBHOOK,
            TOOL_SMELT_ITEM,
            TOOL_MOVE_TO_POSITION,
            TOOL_LIST_INVENTORY,
        ]
        top5 = _pick_security_relevant(camazotz_tools, 5)
        names = {t["name"] for t in top5}
        assert "secrets.leak_config" in names
        assert "tool.hidden_exec" in names

    def test_returns_all_when_n_exceeds_count(self):
        top10 = _pick_security_relevant(self.ARTIFICE_TOOLS, 10)
        assert len(top10) == len(self.ARTIFICE_TOOLS)

    def test_returns_empty_for_empty_list(self):
        assert _pick_security_relevant([], 5) == []

    def test_tie_breaks_are_deterministic_by_name(self):
        tied_tools = [
            {"name": "zeta", "description": "benign", "inputSchema": {"type": "object", "properties": {}}},
            {"name": "alpha", "description": "benign", "inputSchema": {"type": "object", "properties": {}}},
            {"name": "mu", "description": "benign", "inputSchema": {"type": "object", "properties": {}}},
        ]
        top3 = _pick_security_relevant(tied_tools, 3)
        names = [tool["name"] for tool in top3]
        assert names == ["alpha", "mu", "zeta"]
