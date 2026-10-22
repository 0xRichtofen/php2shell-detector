import unittest
from php_audit import classify, normalize, PATTERN, SameOriginRedirect

class TestAudit(unittest.TestCase):
    def test_version(self):
        self.assertEqual(classify("8.3.35"), "BELOW_UPSTREAM_FIX")
        self.assertEqual(classify("8.3.36"), "UPSTREAM_FIXED_VERSION")
        self.assertEqual(classify("7.4.33"), "LEGACY_BRANCH_REVIEW")
        self.assertEqual(classify(None), "UNKNOWN")
    def test_url(self):
        self.assertEqual(normalize("example.com"), "https://example.com/")
        self.assertIsNone(normalize("# comment"))
        with self.assertRaises(ValueError):
            normalize("file:///etc/passwd")
    def test_header(self):
        self.assertEqual(PATTERN.search("PHP/8.5.12").group(0), "PHP/8.5.12")
    def test_redirect(self):
        from urllib.request import Request
        h = SameOriginRedirect()
        self.assertIsNone(h.redirect_request(Request("https://example.com/"), None, 302, "", {}, "https://other.com/"))

if __name__ == "__main__":
    unittest.main()

class TestLiveFingerprint(unittest.TestCase):
    def test_live_header_and_evidence(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from php_audit import scan

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("X-Powered-By", "PHP/8.3.35")
                self.end_headers()
                self.wfile.write(b"OK")

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = scan(f"http://127.0.0.1:{server.server_port}/", 3)
            self.assertEqual(result["php_version"], "8.3.35")
            self.assertEqual(result["version_confidence"], "MEDIUM")
            self.assertIn("header:x-powered-by", result["version_source"])
            self.assertEqual(result["cve_status"], "NOT_CONFIRMED")
        finally:
            server.shutdown()
            server.server_close()

class TestCveEvidence(unittest.TestCase):
    def test_version_without_php_presence(self):
        from php_audit import scan
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'hello')
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            r = scan(f'http://127.0.0.1:{server.server_port}/', 2, paths=['/phpinfo.php'])
            self.assertFalse(r['php_detected'])
            self.assertIsNone(r['evidence_endpoint'])
            self.assertEqual(r['cve_assessment'], 'INCONCLUSIVE')
        finally:
            server.shutdown()
            server.server_close()

    def test_evidence_separation(self):
        from php_audit import scan
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('X-Powered-By', 'PHP/8.3.35')
                self.end_headers()
                self.wfile.write(b'hello')
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            r = scan(f'http://127.0.0.1:{server.server_port}/', 2)
            self.assertEqual(r['version_source'], 'header:x-powered-by')
            self.assertEqual(r['evidence_endpoint'], r['target'])
            self.assertEqual(r['cve_assessment'], 'POTENTIALLY_AFFECTED')
            self.assertEqual(r['cve_status'], 'NOT_CONFIRMED')
        finally:
            server.shutdown()
            server.server_close()
