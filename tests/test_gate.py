"""Unit tests for the HTTP request gate (engine.server): host_allowed,
origin_allowed, and the Handler._gate method that combines them with the
Sec-Fetch-Site check.

These lock in the anti-DNS-rebinding / anti-CSRF behaviour of the local
HTTP interface: a browser page on another origin must not be able to
drive the API just because it can reach 127.0.0.1.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import server                                         # noqa: E402


class _Headers(dict):
    """Minimal stand-in for http.client.HTTPMessage: case-sensitive here
    (tests pass canonical casing) but exposes the .get() the gate uses."""

    def get(self, key, default=None):
        return dict.get(self, key, default)


class _FakeHandler:
    """Just enough of Handler for _gate(): headers + a _send() that
    records what was sent instead of writing to a socket."""

    def __init__(self, headers):
        self.headers = _Headers(headers)
        self.sent = None

    def _send(self, code, body, ctype="application/json"):
        self.sent = (code, body)


class _BoundStateMixin(unittest.TestCase):
    """Saves/restores the module-level _BOUND dict so tests can point the
    gate at whatever bind address they're exercising without leaking
    state into other tests."""

    def setUp(self):
        self._saved_bound = dict(server._BOUND)
        self.addCleanup(lambda: server._BOUND.update(self._saved_bound))


class HostAllowedLoopbackBind(_BoundStateMixin):
    """Bound to 127.0.0.1 (the default): only loopback names/addresses,
    on the bound port, get through."""

    def setUp(self):
        super().setUp()
        server.set_bound_address("127.0.0.1", 8722)

    def test_matching_ip_and_port_allowed(self):
        self.assertTrue(server.host_allowed("127.0.0.1:8722"))

    def test_localhost_name_and_port_allowed(self):
        self.assertTrue(server.host_allowed("localhost:8722"))

    def test_wrong_port_rejected(self):
        self.assertFalse(server.host_allowed("127.0.0.1:9999"))
        self.assertFalse(server.host_allowed("localhost:9999"))

    def test_missing_host_rejected(self):
        self.assertFalse(server.host_allowed(""))
        self.assertFalse(server.host_allowed(None))

    def test_rebinding_hostname_rejected(self):
        # The classic DNS-rebinding case: attacker.example resolves to
        # 127.0.0.1 at request time, but the Host header still names the
        # attacker's hostname, not localhost/127.0.0.1.
        self.assertFalse(server.host_allowed("evil.com:8722"))
        self.assertFalse(server.host_allowed("attacker.example:8722"))

    def test_host_without_a_port_matches_on_name_alone(self):
        # _split_host treats a missing port as "don't care" rather than
        # "must equal the bound port" -- a bare "Host: localhost" (no
        # ":8722") is accepted purely because the name is a loopback
        # name. Documented here so a future change to this is deliberate.
        self.assertTrue(server.host_allowed("localhost"))
        self.assertTrue(server.host_allowed("127.0.0.1"))
        self.assertFalse(server.host_allowed("evil.com"))

    def test_ipv6_loopback_literal_allowed(self):
        self.assertTrue(server.host_allowed("[::1]:8722"))

    def test_case_insensitive(self):
        self.assertTrue(server.host_allowed("LOCALHOST:8722"))


class HostAllowedWildcardBind(_BoundStateMixin):
    """Bound to 0.0.0.0 / :: (listening on every interface): loopback
    names and any syntactic IP literal are accepted, but not arbitrary
    hostnames -- the server can't tell in advance which of its own
    interface addresses a legitimate client will use."""

    def test_ipv4_wildcard_allows_loopback_and_ip_literals(self):
        server.set_bound_address("0.0.0.0", 8722)
        self.assertTrue(server.host_allowed("127.0.0.1:8722"))
        self.assertTrue(server.host_allowed("localhost:8722"))
        self.assertTrue(server.host_allowed("10.0.0.5:8722"))
        self.assertTrue(server.host_allowed("[::1]:8722"))
        self.assertTrue(server.host_allowed("[2001:db8::1]:8722"))

    def test_ipv4_wildcard_rejects_hostnames(self):
        server.set_bound_address("0.0.0.0", 8722)
        self.assertFalse(server.host_allowed("attacker.example:8722"))
        self.assertFalse(server.host_allowed("router.lan:8722"))

    def test_ipv6_wildcard_behaves_the_same(self):
        server.set_bound_address("::", 8722)
        self.assertTrue(server.host_allowed("127.0.0.1:8722"))
        self.assertTrue(server.host_allowed("[::1]:8722"))
        self.assertFalse(server.host_allowed("attacker.example:8722"))

    def test_wildcard_still_enforces_port(self):
        server.set_bound_address("0.0.0.0", 8722)
        self.assertFalse(server.host_allowed("127.0.0.1:9999"))


class HostAllowedSpecificLanBind(_BoundStateMixin):
    """Bound to one specific LAN address: only that host (any port
    variant of it) is allowed -- notably, loopback stops working."""

    def setUp(self):
        super().setUp()
        server.set_bound_address("192.168.1.50", 8722)

    def test_bound_address_allowed(self):
        self.assertTrue(server.host_allowed("192.168.1.50:8722"))

    def test_loopback_rejected_when_bound_elsewhere(self):
        self.assertFalse(server.host_allowed("127.0.0.1:8722"))
        self.assertFalse(server.host_allowed("localhost:8722"))

    def test_other_ip_rejected(self):
        self.assertFalse(server.host_allowed("192.168.1.51:8722"))
        self.assertFalse(server.host_allowed("10.0.0.5:8722"))

    def test_wrong_port_rejected(self):
        self.assertFalse(server.host_allowed("192.168.1.50:9999"))


class OriginAllowed(_BoundStateMixin):

    def setUp(self):
        super().setUp()
        server.set_bound_address("127.0.0.1", 8722)

    def test_no_origin_header_allowed(self):
        # Not every legitimate request carries Origin (plain navigations,
        # same-origin requests in older browsers, non-browser tooling).
        self.assertTrue(server.origin_allowed("", "127.0.0.1:8722"))
        self.assertTrue(server.origin_allowed(None, "127.0.0.1:8722"))

    def test_null_origin_rejected(self):
        # Sandboxed iframes / some redirects send the literal string
        # "null" as Origin.
        self.assertFalse(server.origin_allowed("null", "127.0.0.1:8722"))

    def test_file_scheme_rejected(self):
        self.assertFalse(server.origin_allowed("file://", "127.0.0.1:8722"))

    def test_extension_scheme_rejected(self):
        self.assertFalse(server.origin_allowed(
            "chrome-extension://abcdefghijklmnop", "127.0.0.1:8722"))

    def test_matching_origin_allowed(self):
        self.assertTrue(server.origin_allowed(
            "http://127.0.0.1:8722", "127.0.0.1:8722"))

    def test_matching_origin_by_name_allowed(self):
        self.assertTrue(server.origin_allowed(
            "http://localhost:8722", "localhost:8722"))

    def test_cross_site_origin_rejected(self):
        self.assertFalse(server.origin_allowed(
            "http://evil.com:8722", "127.0.0.1:8722"))

    def test_origin_host_mismatch_against_host_header_rejected(self):
        # Origin says localhost but the request claims to be addressed
        # to 127.0.0.1 -- inconsistent, refuse it.
        self.assertFalse(server.origin_allowed(
            "http://localhost:8722", "127.0.0.1:8722"))

    def test_wrong_port_in_origin_rejected(self):
        self.assertFalse(server.origin_allowed(
            "http://127.0.0.1:9999", "127.0.0.1:8722"))

    def test_https_scheme_also_accepted(self):
        self.assertTrue(server.origin_allowed(
            "https://127.0.0.1:8722", "127.0.0.1:8722"))

    def test_garbage_origin_rejected(self):
        self.assertFalse(server.origin_allowed("not-a-url", "127.0.0.1:8722"))


class GateHostCheck(_BoundStateMixin):
    """Handler._gate(): the Host header gate, checked first (421)."""

    def setUp(self):
        super().setUp()
        server.set_bound_address("127.0.0.1", 8722)

    def test_bad_host_returns_421(self):
        fh = _FakeHandler({"Host": "evil.com:8722"})
        self.assertFalse(server.Handler._gate(fh))
        self.assertEqual(fh.sent[0], 421)

    def test_missing_host_returns_421(self):
        fh = _FakeHandler({})
        self.assertFalse(server.Handler._gate(fh))
        self.assertEqual(fh.sent[0], 421)

    def test_good_host_no_other_headers_allowed(self):
        fh = _FakeHandler({"Host": "127.0.0.1:8722"})
        self.assertTrue(server.Handler._gate(fh))
        self.assertIsNone(fh.sent)


class GateSecFetchSiteCheck(_BoundStateMixin):
    """Handler._gate(): Sec-Fetch-Site is checked before Origin, and a
    cross-site value is refused outright regardless of Origin."""

    def setUp(self):
        super().setUp()
        server.set_bound_address("127.0.0.1", 8722)

    def test_cross_site_rejected_with_403(self):
        fh = _FakeHandler({"Host": "127.0.0.1:8722",
                           "Sec-Fetch-Site": "cross-site"})
        self.assertFalse(server.Handler._gate(fh))
        self.assertEqual(fh.sent[0], 403)

    def test_cross_site_rejected_even_with_matching_origin(self):
        # Belt and braces: even if Origin somehow matched, a browser
        # that says cross-site is telling the truth about the request's
        # provenance and must not be second-guessed.
        fh = _FakeHandler({"Host": "127.0.0.1:8722",
                           "Sec-Fetch-Site": "cross-site",
                           "Origin": "http://127.0.0.1:8722"})
        self.assertFalse(server.Handler._gate(fh))
        self.assertEqual(fh.sent[0], 403)

    def test_same_origin_allowed(self):
        fh = _FakeHandler({"Host": "127.0.0.1:8722",
                           "Sec-Fetch-Site": "same-origin"})
        self.assertTrue(server.Handler._gate(fh))

    def test_same_site_allowed(self):
        fh = _FakeHandler({"Host": "127.0.0.1:8722",
                           "Sec-Fetch-Site": "same-site"})
        self.assertTrue(server.Handler._gate(fh))

    def test_none_value_allowed(self):
        # "none" means the browser itself typed the URL / used a
        # bookmark -- not driven by another page.
        fh = _FakeHandler({"Host": "127.0.0.1:8722",
                           "Sec-Fetch-Site": "none"})
        self.assertTrue(server.Handler._gate(fh))

    def test_absent_header_falls_through_to_origin_check(self):
        # Older browsers and non-browser clients don't send
        # Sec-Fetch-Site at all; the gate must not require it.
        fh = _FakeHandler({"Host": "127.0.0.1:8722"})
        self.assertTrue(server.Handler._gate(fh))


class GateOriginCheck(_BoundStateMixin):
    """Handler._gate(): Origin is checked last, after Host and
    Sec-Fetch-Site both pass."""

    def setUp(self):
        super().setUp()
        server.set_bound_address("127.0.0.1", 8722)

    def test_cross_origin_rejected_with_403(self):
        fh = _FakeHandler({"Host": "127.0.0.1:8722",
                           "Origin": "http://evil.com:8722"})
        self.assertFalse(server.Handler._gate(fh))
        self.assertEqual(fh.sent[0], 403)

    def test_matching_origin_allowed(self):
        fh = _FakeHandler({"Host": "127.0.0.1:8722",
                           "Origin": "http://127.0.0.1:8722"})
        self.assertTrue(server.Handler._gate(fh))

    def test_null_origin_rejected(self):
        fh = _FakeHandler({"Host": "127.0.0.1:8722", "Origin": "null"})
        self.assertFalse(server.Handler._gate(fh))
        self.assertEqual(fh.sent[0], 403)


class HostAllowedLooseIpLiteralCheck(_BoundStateMixin):
    """_is_ip_literal() is a syntactic check only (used to decide whether
    a Host string "looks like" an address rather than a hostname when
    bound to a wildcard address); it does not validate octet ranges. Not
    exploitable on its own -- a Host header still has to reach the
    process over a socket bound to that literal interface, or be one of
    the fixed loopback names -- but locked in here so a tightening or
    loosening of the check is a deliberate change, not a surprise."""

    def test_out_of_range_octets_still_treated_as_ip_shaped(self):
        self.assertTrue(server._is_ip_literal("999.999.999.999"))

    def test_real_hostname_not_ip_shaped(self):
        self.assertFalse(server._is_ip_literal("attacker.example"))


if __name__ == "__main__":
    unittest.main()
