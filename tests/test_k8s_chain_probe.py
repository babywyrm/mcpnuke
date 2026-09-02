"""Tests for K8s namespace boundary chain probe."""

from mcpnuke.checks.k8s_chain_probe import k8s_chain_probe


class TestK8sChainProbe:
    def test_detects_cross_namespace_movement(self, result_with_tools):
        result = result_with_tools([
            {
                "name": "list_secrets",
                "description": "List secrets in namespace",
                "inputSchema": {
                    "type": "object",
                    "properties": {"namespace": {"type": "string"}},
                },
            },
            {
                "name": "create_pod",
                "description": "Create pod in namespace",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "namespace": {"type": "string"},
                        "image": {"type": "string"},
                    },
                },
            },
        ])
        k8s_chain_probe(result)
        # Should detect potential cross-namespace chain
        assert any("k8s" in f.check for f in result.findings)

    def test_clean_single_namespace_no_finding(self, result_with_tools):
        result = result_with_tools([
            {
                "name": "get_pod",
                "description": "Get pod in current namespace",
                "inputSchema": {"type": "object"},
            },
        ])
        k8s_chain_probe(result)
        assert not any("k8s_chain" in f.check for f in result.findings)

    def test_timing_recorded(self, result_with_tools):
        result = result_with_tools([])
        k8s_chain_probe(result)
        assert "k8s_chain_probe" in result.timings
