"""Tests for paginated MCP list enumeration."""

from __future__ import annotations

import pytest

from mcpnuke.core.enumerator import _paginated_list, DEFAULT_MAX_PAGES
from mcpnuke.core.models import TargetResult


class FakeSession:
    """Minimal session stub returning configurable paginated responses."""

    def __init__(self, pages: list[dict]):
        self._pages = pages
        self._call_idx = 0

    def call(self, method, params=None, timeout=15, retries=2):
        if self._call_idx >= len(self._pages):
            return None
        page = self._pages[self._call_idx]
        self._call_idx += 1
        return page

    def notify(self, method, params=None):
        pass


class TestPaginatedList:
    """_paginated_list follows nextCursor and respects page cap."""

    def test_single_page_no_cursor(self):
        pages = [{"result": {"tools": [{"name": "t1"}, {"name": "t2"}]}}]
        session = FakeSession(pages)
        items, truncated = _paginated_list(session, "tools/list", max_pages=20)
        assert len(items) == 2
        assert not truncated

    def test_multi_page_pagination(self):
        pages = [
            {"result": {"tools": [{"name": "t1"}], "nextCursor": "page2"}},
            {"result": {"tools": [{"name": "t2"}], "nextCursor": "page3"}},
            {"result": {"tools": [{"name": "t3"}]}},
        ]
        session = FakeSession(pages)
        items, truncated = _paginated_list(session, "tools/list", max_pages=20)
        assert len(items) == 3
        assert [t["name"] for t in items] == ["t1", "t2", "t3"]
        assert not truncated

    def test_truncated_at_page_cap(self):
        pages = [
            {"result": {"tools": [{"name": f"t{i}"}], "nextCursor": f"page{i+1}"}}
            for i in range(5)
        ]
        session = FakeSession(pages)
        items, truncated = _paginated_list(session, "tools/list", max_pages=3)
        assert len(items) == 3
        assert truncated

    def test_empty_result(self):
        pages = [{"result": {"tools": []}}]
        session = FakeSession(pages)
        items, truncated = _paginated_list(session, "tools/list")
        assert items == []
        assert not truncated

    def test_no_response(self):
        session = FakeSession([])
        items, truncated = _paginated_list(session, "tools/list")
        assert items == []
        assert not truncated

    def test_resources_pagination(self):
        pages = [
            {"result": {"resources": [{"uri": "r1"}], "nextCursor": "c2"}},
            {"result": {"resources": [{"uri": "r2"}]}},
        ]
        session = FakeSession(pages)
        items, truncated = _paginated_list(session, "resources/list")
        assert len(items) == 2
        assert not truncated

    def test_default_max_pages_constant(self):
        assert DEFAULT_MAX_PAGES == 20


class TestEnumerateServerPagination:
    """enumerate_server uses _paginated_list and emits truncation findings."""

    def test_truncation_finding_emitted(self, result_with_tools):
        from mcpnuke.core.enumerator import enumerate_server

        pages_tools = [
            {"result": {"tools": [{"name": f"t{i}"}], "nextCursor": f"p{i+1}"}}
            for i in range(5)
        ]
        init_resp = {
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "test", "version": "1.0"},
                "capabilities": {"tools": {}},
            }
        }

        class PaginatedSession:
            def __init__(self):
                self._tool_idx = 0

            def call(self, method, params=None, timeout=15, retries=2):
                if method == "initialize":
                    return init_resp
                if method == "tools/list":
                    if self._tool_idx < len(pages_tools):
                        page = pages_tools[self._tool_idx]
                        self._tool_idx += 1
                        return page
                    return None
                if method in ("resources/list", "prompts/list"):
                    return {"result": {method.split("/")[0]: []}}
                return None

            def notify(self, method, params=None):
                pass

        result = result_with_tools([])
        session = PaginatedSession()
        enumerate_server(session, result, max_pages=3)

        truncation_findings = [f for f in result.findings if f.check == "enumeration"]
        assert len(truncation_findings) >= 1
        assert "truncated" in truncation_findings[0].title.lower()
