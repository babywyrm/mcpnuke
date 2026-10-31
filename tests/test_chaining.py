"""Chaining checks: tool-name extraction, attack-chain evidence, multi-vector."""

from mcpnuke.core.models import TargetResult

# ---------------------------------------------------------------------------
# A1: _extract_tool_names validates against actual tools
# ---------------------------------------------------------------------------

class TestExtractToolNamesFiltering:
    def test_rejects_descriptive_fragments(self):
        from mcpnuke.checks.chaining import _extract_tool_names

        r = TargetResult(url="http://test")
        r.tools = [{"name": "audit.perform_action"}, {"name": "egress.fetch_url"}]
        r.add("input_sanitization", "HIGH",
              "Tool 'audit.perform_action' has execution-like param: command")
        r.add("input_sanitization", "HIGH",
              "Tool 'egress.fetch_url' reflects input via param 'url'")

        valid = {"audit.perform_action", "egress.fetch_url", "audit", "egress"}
        names = _extract_tool_names(r.findings, "input_sanitization", valid)

        assert "audit.perform_action" in names
        assert "egress.fetch_url" in names
        for n in names:
            assert " " not in n, f"Descriptive fragment leaked: {n!r}"
            assert n.split(".")[0] in valid or n in valid

    def test_no_filter_without_valid_names(self):
        """Backward compat: without valid_names, all regex matches pass."""
        from mcpnuke.checks.chaining import _extract_tool_names

        r = TargetResult(url="http://test")
        r.add("code_execution", "CRITICAL",
              "Dangerous capability [shell_exec]: 'execute_command'")

        names = _extract_tool_names(r.findings, "code_execution")
        assert "execute_command" in names

    def test_prefix_match_for_dotted_names(self):
        from mcpnuke.checks.chaining import _extract_tool_names

        r = TargetResult(url="http://test")
        r.add("ssrf_probe", "HIGH", "Tool 'egress.fetch_url' has url param")

        valid = {"egress.fetch_url", "egress"}
        names = _extract_tool_names(r.findings, "ssrf_probe", valid)
        assert "egress.fetch_url" in names


class TestAttackChainsFiltersEvidence:
    def test_evidence_tools_excludes_garbage(self):
        from mcpnuke.checks.chaining import check_attack_chains

        r = TargetResult(url="http://test")
        r.tools = [
            {"name": "audit.perform_action", "inputSchema": {}},
            {"name": "hallucination.execute_plan", "inputSchema": {}},
        ]
        r.add("input_sanitization", "HIGH",
              "Tool 'hallucination.execute_plan' has execution-like param: command")
        r.add("code_execution", "CRITICAL",
              "Dangerous capability [shell_exec]: 'hallucination.execute_plan'")

        check_attack_chains(r)
        chain = r.attack_chains[0]
        for t in chain.evidence_tools:
            assert " " not in t, f"Garbage in evidence_tools: {t!r}"
        assert "hallucination.execute_plan" in chain.evidence_tools


# ---------------------------------------------------------------------------
# A2: check_multi_vector expanded dangerous set
# ---------------------------------------------------------------------------

class TestMultiVectorExpanded:
    def test_active_injection_counted(self):
        from mcpnuke.checks.chaining import check_multi_vector

        r = TargetResult(url="http://test")
        r.add("active_prompt_injection", "CRITICAL", "test")
        r.add("token_theft", "HIGH", "test")
        check_multi_vector(r)

        mv = [f for f in r.findings if f.check == "multi_vector"]
        assert len(mv) >= 1

    def test_tool_response_injection_counted(self):
        from mcpnuke.checks.chaining import check_multi_vector

        r = TargetResult(url="http://test")
        r.add("tool_response_injection", "HIGH", "test")
        r.add("exfil_flow", "HIGH", "test")
        check_multi_vector(r)

        mv = [f for f in r.findings if f.check == "multi_vector"]
        assert len(mv) >= 1

    def test_injection_exfil_chain_with_active_checks(self):
        from mcpnuke.checks.chaining import check_multi_vector

        r = TargetResult(url="http://test")
        r.add("active_prompt_injection", "CRITICAL", "test")
        r.add("response_credentials", "HIGH", "test")
        check_multi_vector(r)

        mv = [f for f in r.findings if f.check == "multi_vector"]
        chain_findings = [f for f in mv if "injection + exfiltration" in f.title]
        assert len(chain_findings) >= 1


# ---------------------------------------------------------------------------
# A3: deep_rug_pull priority sorting and expanded limit
# ---------------------------------------------------------------------------
