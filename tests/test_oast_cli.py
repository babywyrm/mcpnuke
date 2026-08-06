"""The oracle is useless if an operator cannot reach it.

The listener binds locally, but the URL planted in the payload has to be an
address the *target* can route to. A container cannot resolve the scanner's
loopback and a host across a network cannot reach a private one, so the
advertised host must be settable independently of the bind.

Opening a listening socket and inducing a target to send data outward is also
not something to do by default, so it is opt-in.
"""

from __future__ import annotations

from mcpnuke.cli import build_parser


def _parse(*argv: str):
    return build_parser().parse_args(["--targets", "http://t/mcp", *argv])


class TestTheFlagsExist:
    def test_oast_is_off_by_default(self):
        assert not _parse().oast

    def test_it_can_be_enabled(self):
        assert _parse("--oast").oast

    def test_the_advertised_host_defaults_to_unset(self):
        assert _parse().oast_host is None

    def test_the_advertised_host_can_be_given(self):
        assert _parse("--oast-host", "host.docker.internal").oast_host == "host.docker.internal"

    def test_the_bind_port_defaults_to_ephemeral(self):
        assert _parse().oast_port == 0

    def test_a_fixed_port_can_be_given_for_a_firewall_hole(self):
        assert _parse("--oast-port", "8899").oast_port == 8899


class TestTheHelpExplainsTheConstraint:
    def _help_for(self, option: str) -> str:
        for action in build_parser()._actions:
            if option in action.option_strings:
                return action.help or ""
        raise AssertionError(f"{option} not found")

    def test_oast_says_what_it_proves(self):
        text = self._help_for("--oast").lower()

        assert "egress" in text or "exfil" in text

    def test_oast_host_explains_target_reachability(self):
        text = self._help_for("--oast-host").lower()

        assert "reach" in text or "container" in text
