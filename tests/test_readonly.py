"""Unit tests for read-only mode (issue #70): a session-level flag that
refuses server-side export and report-writing routes.

Covers the pure guard (engine.server._blocked_by_readonly), the Handler-level
refusal (proving a blocked route is turned away before it ever touches the
session's filesystem or case, not merely hidden by the UI), Session.read_only
/ Session.state(), and the run.py --read-only flag.
"""

import argparse
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import server                                         # noqa: E402


BLOCKED_PATHS = (
    "/api/export",
    "/api/export/file",
    "/api/export/folder",
    "/api/export/manifest",
    "/api/report/write",
)

UNRELATED_PATHS = (
    "/api/dir",
    "/api/bookmark",
    "/api/tag",
    "/api/case/open",
    "/api/registry/report",
    "/api/whoami",
    "/api/report",  # GET-only in-memory render, not the POST write route
)


class BlockedByReadonlyPureFunction(unittest.TestCase):
    """_blocked_by_readonly() is a plain (bool, str) -> bool function, so
    these don't need a Handler, a Session, or any I/O."""

    def test_export_and_report_write_blocked_when_read_only(self):
        for path in BLOCKED_PATHS:
            with self.subTest(path=path):
                self.assertTrue(server._blocked_by_readonly(True, path))

    def test_same_paths_allowed_when_not_read_only(self):
        # This is what keeps normal-mode export/report behaviour exactly as
        # it was: the guard simply never fires when the flag is off.
        for path in BLOCKED_PATHS:
            with self.subTest(path=path):
                self.assertFalse(server._blocked_by_readonly(False, path))

    def test_unrelated_routes_never_blocked(self):
        # Read-only mode must not broaden into unrelated case/tag/bookmark
        # writes -- only export and report writing are in scope.
        for path in UNRELATED_PATHS:
            with self.subTest(path=path):
                self.assertFalse(server._blocked_by_readonly(True, path))
                self.assertFalse(server._blocked_by_readonly(False, path))

    def test_unknown_or_malformed_path_not_matched(self):
        # A typo'd or unrelated path must fall through to the normal 404
        # dispatch rather than being swallowed by the guard.
        for path in ("/api/exportfile", "/api/export/file/", "/api/EXPORT",
                     "", "/api/export/", "not-a-path"):
            with self.subTest(path=path):
                self.assertFalse(server._blocked_by_readonly(True, path))


class _Headers(dict):
    def get(self, key, default=None):
        return dict.get(self, key, default)


class _RefusingCase:
    """A case stub that records what was logged, and blows up on anything
    else -- if a blocked route reached real export/report logic it would
    try to touch things this stub does not provide."""

    def __init__(self):
        self.logged = []

    def log(self, action, detail=None):
        self.logged.append((action, detail))

    def __getattr__(self, name):
        raise AssertionError(
            "case.%s was touched -- the read-only guard should have "
            "refused before any real export/report logic ran" % name)


class _RefusingSession:
    """A session stub whose write-triggering members raise if touched, so
    a test can prove the guard short-circuits _api_post before dispatch."""

    def __init__(self, read_only, case=None):
        self.read_only = read_only
        self.case = case

    def __getattr__(self, name):
        raise AssertionError(
            "session.%s was touched -- the read-only guard should have "
            "refused before any real export/report logic ran" % name)


class _FakeHandler:
    """Just enough of Handler for _api_post()'s guard: a canned session and
    a _send() that records what was sent instead of writing to a socket.
    _readonly_refusal is the real Handler method (not reimplemented here),
    so this exercises the exact code the server runs."""

    _readonly_refusal = server.Handler._readonly_refusal

    def __init__(self, session):
        self._sess = session
        self.sent = None

    def _session(self):
        return self._sess

    def _send(self, code, body, ctype="application/json"):
        self.sent = (code, body)
        return None


class HandlerLevelRefusal(unittest.TestCase):
    """Direct calls into Handler._api_post -- the same entry point a raw
    HTTP request reaches -- proving the refusal is server-side and
    unconditional, not something only the UI enforces."""

    def test_export_file_refused_without_touching_session(self):
        fh = _FakeHandler(_RefusingSession(read_only=True))
        server.Handler._api_post(fh, "/api/export/file", {})
        self.assertEqual(fh.sent[0], 403)
        self.assertIn("error", fh.sent[1])

    def test_export_folder_refused(self):
        fh = _FakeHandler(_RefusingSession(read_only=True))
        server.Handler._api_post(fh, "/api/export/folder", {})
        self.assertEqual(fh.sent[0], 403)

    def test_export_manifest_refused(self):
        fh = _FakeHandler(_RefusingSession(read_only=True))
        server.Handler._api_post(fh, "/api/export/manifest", {})
        self.assertEqual(fh.sent[0], 403)

    def test_raw_byte_range_export_refused(self):
        fh = _FakeHandler(_RefusingSession(read_only=True))
        server.Handler._api_post(fh, "/api/export", {})
        self.assertEqual(fh.sent[0], 403)

    def test_report_write_refused(self):
        fh = _FakeHandler(_RefusingSession(read_only=True))
        server.Handler._api_post(fh, "/api/report/write", {})
        self.assertEqual(fh.sent[0], 403)

    def test_refusal_is_logged_to_an_open_case(self):
        case = _RefusingCase()
        fh = _FakeHandler(_RefusingSession(read_only=True, case=case))
        server.Handler._api_post(fh, "/api/export/file", {})
        self.assertEqual(fh.sent[0], 403)
        self.assertEqual(len(case.logged), 1)
        action, detail = case.logged[0]
        self.assertEqual(action, "readonly.refused")
        self.assertEqual(detail["path"], "/api/export/file")

    def test_no_case_open_still_refuses_without_error(self):
        # No case to log into -- the refusal must not itself raise.
        fh = _FakeHandler(_RefusingSession(read_only=True, case=None))
        server.Handler._api_post(fh, "/api/report/write", {})
        self.assertEqual(fh.sent[0], 403)

    def test_malformed_body_on_a_blocked_route_still_refused_not_500(self):
        # The guard runs before any body parsing, so a missing/invalid
        # body on export's normally-required fields doesn't matter: the
        # request never reaches the code that would need them.
        fh = _FakeHandler(_RefusingSession(read_only=True))
        server.Handler._api_post(fh, "/api/export", {"offset": "not-a-number"})
        self.assertEqual(fh.sent[0], 403)


class SessionReadOnlyProperty(unittest.TestCase):
    """Session.read_only reads the live module flag rather than capturing
    it at construction time -- required because the module-level SESSION
    singleton is built at import time, before serve() parses --read-only."""

    def setUp(self):
        self._saved = server.READ_ONLY
        self.addCleanup(lambda: setattr(server, "READ_ONLY", self._saved))

    def test_defaults_off(self):
        server.READ_ONLY = False
        s = server.Session()
        self.assertFalse(s.read_only)

    def test_reflects_flag_set_after_construction(self):
        s = server.Session()
        server.READ_ONLY = True
        self.assertTrue(s.read_only)

    def test_state_reports_read_only_with_no_case_and_no_evidence(self):
        server.READ_ONLY = True
        s = server.Session()
        self.assertTrue(s.state()["read_only"])
        server.READ_ONLY = False
        self.assertFalse(s.state()["read_only"])


class ServeSetsTheModuleFlag(unittest.TestCase):

    def setUp(self):
        self._saved = server.READ_ONLY
        self.addCleanup(lambda: setattr(server, "READ_ONLY", self._saved))

    def test_serve_read_only_true_sets_the_flag_before_serving(self):
        httpd = mock.Mock()
        httpd.serve_forever.side_effect = KeyboardInterrupt
        with mock.patch.object(server, "_Server", return_value=httpd), \
             mock.patch.object(server, "set_bound_address"):
            server.READ_ONLY = False
            server.serve("127.0.0.1", 0, None, None, read_only=True)
        self.assertTrue(server.READ_ONLY)

    def test_serve_defaults_to_read_only_false(self):
        httpd = mock.Mock()
        httpd.serve_forever.side_effect = KeyboardInterrupt
        with mock.patch.object(server, "_Server", return_value=httpd), \
             mock.patch.object(server, "set_bound_address"):
            server.READ_ONLY = True
            server.serve("127.0.0.1", 0, None, None)
        self.assertFalse(server.READ_ONLY)


class RunPyReadOnlyFlag(unittest.TestCase):
    """run.py's argument parser accepts --read-only and passes it through
    to engine.server.serve()."""

    def _parser(self):
        ap = argparse.ArgumentParser()
        ap.add_argument("image", nargs="?")
        ap.add_argument("--host", default="127.0.0.1")
        ap.add_argument("--port", type=int, default=8722)
        ap.add_argument("--examiner", default=None)
        ap.add_argument("--browser", action="store_true")
        ap.add_argument("--no-browser", action="store_true")
        ap.add_argument("--read-only", action="store_true")
        return ap

    def test_flag_defaults_false(self):
        args = self._parser().parse_args([])
        self.assertFalse(args.read_only)

    def test_flag_can_be_set(self):
        args = self._parser().parse_args(["--read-only"])
        self.assertTrue(args.read_only)

    def test_main_forwards_the_flag_to_serve(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sys.path.insert(0, root)
        import importlib
        run_mod = importlib.import_module("run")
        try:
            with mock.patch.object(run_mod, "serve") as serve_mock, \
                 mock.patch.object(sys, "argv", ["run.py", "--read-only"]):
                run_mod.main()
            self.assertTrue(serve_mock.called)
            self.assertTrue(serve_mock.call_args.kwargs.get("read_only"))
        finally:
            sys.modules.pop("run", None)


if __name__ == "__main__":
    unittest.main()
