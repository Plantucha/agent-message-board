import importlib.util
from importlib.machinery import SourceFileLoader
import os
import subprocess
import sys
import socket
import tempfile
import time
import unittest
from pathlib import Path
from urllib import error as urlerror
from urllib import request as urlrequest


SCRIPT = Path(__file__).resolve().parents[1] / "bin" / "agent-board"
LOADER = SourceFileLoader("agent_board", str(SCRIPT))
SPEC = importlib.util.spec_from_loader("agent_board", LOADER)
board_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = board_module
SPEC.loader.exec_module(board_module)


class BoardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="agent-board-test-")
        self.root = Path(self.tmp.name)
        self.db = self.root / "board.db"
        self.board = board_module.Board(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def test_concurrent_writers(self):
        thread_id, _ = self.board.create_thread("Concurrent writers", ["test"], "owner:test", None)
        env = dict(os.environ, AGENT_BOARD_DB=str(self.db), PYTHONDONTWRITEBYTECODE="1")
        processes = [
            subprocess.Popen(
                [sys.executable, str(SCRIPT), "--as", f"writer-{i}", "post", str(thread_id), f"entry {i}", "--kind", "finding"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                text=True,
            )
            for i in range(16)
        ]
        results = [p.communicate(timeout=30) + (p.returncode,) for p in processes]
        failures = [result for result in results if result[2] != 0]
        self.assertEqual(failures, [])
        _thread, rows = self.board.read_thread(str(thread_id), "reader:test")
        self.assertEqual(len(rows), 16)
        self.assertEqual(len({row["id"] for row in rows}), 16)

    def test_thread_and_tag_subscriptions(self):
        thread_id, _ = self.board.create_thread("Toy model training", ["training"], "owner:test", None)
        self.board.subscribe("reader:direct", str(thread_id), from_start=True)
        self.board.subscribe("reader:tag", "tag:training")
        self.board.post(str(thread_id), "writer:test", "The first finding", "finding")
        direct = self.board.inbox("reader:direct")
        tagged = self.board.inbox("reader:tag")
        self.assertEqual([item["body"] for item in direct], ["The first finding"])
        self.assertEqual([item["body"] for item in tagged], ["The first finding"])
        self.assertEqual(self.board.inbox("reader:direct"), [])

    def test_mention_delivers_without_subscription(self):
        thread_id, _ = self.board.create_thread("Mention", ["test"], "owner:test", None)
        self.board.post(str(thread_id), "writer:test", "@claude:toy-model please check the parity result", "question")
        received = self.board.inbox("claude:toy-model")
        self.assertEqual(len(received), 1)
        self.assertIn("parity result", received[0]["body"])

    def test_secret_filter_refuses_api_key_bearer_and_password_patterns(self):
        with self.assertRaisesRegex(ValueError, "Post refused"):
            self.board.post("missing", "writer:test", "api_key=" + "A" * 40)
        with self.assertRaisesRegex(ValueError, "Post refused"):
            board_module.validate_content(None, "Authorization: Bearer " + "x" * 30)
        with self.assertRaisesRegex(ValueError, "Post refused"):
            board_module.validate_content(None, "password=" + "B" * 20)
        with self.assertRaisesRegex(ValueError, "Post refused"):
            board_module.validate_content(None, '{"client_secret": "' + "C" * 24 + '"}')

    def test_jobdir_pointer_is_appended_for_subscriber(self):
        jobdir = self.root / "job"
        jobdir.mkdir()
        thread_id, _ = self.board.create_thread("Pointer", ["test"], "owner:test", None)
        self.board.subscribe("reader:job", str(thread_id), str(jobdir))
        self.board.post(str(thread_id), "writer:test", "Fresh evidence", "finding")
        pointer = (jobdir / "BOARD-INBOX.md").read_text()
        self.assertIn(f"thread #{thread_id}", pointer)
        self.assertIn("agent-board read", pointer)

    def test_archived_thread_retains_entries_and_rejects_new_posts(self):
        thread_id, _ = self.board.create_thread("Archive me", ["test"], "owner:test", "Keep this entry")
        self.assertEqual(self.board.archive(str(thread_id)), 1)
        thread, entries = self.board.read_thread(str(thread_id), "reader:test")
        self.assertTrue(thread["archived_at"])
        self.assertEqual([entry["body"] for entry in entries], ["Keep this entry"])
        with self.assertRaisesRegex(ValueError, "is archived"):
            self.board.post(str(thread_id), "writer:test", "No post")

    def test_web_view_is_read_only_and_served_on_loopback(self):
        self.board.create_thread("Web <safe>", ["test"], "owner:test", "<script>alert(1)</script>")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        env = dict(os.environ, AGENT_BOARD_DB=str(self.db), PYTHONDONTWRITEBYTECODE="1")
        proc = subprocess.Popen(
            [sys.executable, str(SCRIPT), "--as", "web:test", "web", "--port", str(port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
        )
        try:
            page = None
            for _ in range(50):
                try:
                    with urlrequest.urlopen(f"http://127.0.0.1:{port}/", timeout=1) as response:
                        page = response.read().decode()
                        csp = response.headers["Content-Security-Policy"]
                    break
                except OSError:
                    if proc.poll() is not None:
                        break
                    time.sleep(0.05)
            self.assertIsNotNone(page)
            self.assertIn("never instructions", page)
            self.assertIn("script-src 'self'", csp)
            with urlrequest.urlopen(f"http://127.0.0.1:{port}/api/board", timeout=2) as response:
                import json
                data = json.load(response)
            self.assertEqual(data["schemaVersion"], 2)
            self.assertEqual(data["threads"][0]["entries"][0]["body"], "<script>alert(1)</script>")
            with urlrequest.urlopen(f"http://127.0.0.1:{port}/assets/app.js", timeout=2) as response:
                self.assertIn("const esc", response.read().decode())
            req = urlrequest.Request(f"http://127.0.0.1:{port}/api/board", data=b"write", method="POST")
            with self.assertRaises(urlerror.HTTPError) as raised:
                urlrequest.urlopen(req, timeout=2)
            self.assertEqual(raised.exception.code, 501)
        finally:
            proc.terminate()
            proc.communicate(timeout=5)

    def test_agent_names_are_case_insensitive(self):
        thread_id, _ = self.board.create_thread("Case", ["test"], "owner:test", None)
        self.board.subscribe("Reader", str(thread_id), from_start=True)
        self.board.post(str(thread_id), "Writer", "first", "note")
        self.board.post(str(thread_id), "writer", "second", "note")
        conn = self.board.connect()
        try:
            authors = {row[0] for row in conn.execute("SELECT author FROM entries")}
        finally:
            conn.close()
        self.assertEqual(authors, {"writer"})
        self.assertEqual([item["body"] for item in self.board.inbox("reader")], ["first", "second"])
        self.assertEqual(self.board.inbox("READER"), [])

    def test_existing_mixed_case_names_fold_once_and_keep_one_receipt(self):
        thread_id, _ = self.board.create_thread("Legacy", ["test"], "owner:test", None)
        entry_id = self.board.post(str(thread_id), "writer", "old", "note")
        conn = self.board.connect()
        try:
            conn.execute("UPDATE entries SET author='Heron'")
            conn.execute("INSERT INTO read_receipts(agent,entry_id,read_at) VALUES('Heron',?,'t'),('heron',?,'t')",
                         (entry_id, entry_id))
            conn.execute("DELETE FROM events WHERE kind='agent-case-v1'")
        finally:
            conn.close()
        board_module.Board(self.db)
        conn = self.board.connect()
        try:
            self.assertEqual([r[0] for r in conn.execute("SELECT author FROM entries")], ["heron"])
            self.assertEqual([r[0] for r in conn.execute("SELECT agent FROM read_receipts")], ["heron"])
        finally:
            conn.close()

    def test_as_is_accepted_after_the_subcommand(self):
        self.assertEqual(board_module.hoist_as(["post", "8", "--as", "kestrel", "-"]),
                         ["--as", "kestrel", "post", "8", "-"])
        self.assertEqual(board_module.hoist_as(["post", "8", "--as=kestrel", "body"]),
                         ["--as=kestrel", "post", "8", "body"])
        self.assertEqual(board_module.hoist_as(["post", "8", "--", "--as", "x"]),
                         ["post", "8", "--", "--as", "x"])
        thread_id, _ = self.board.create_thread("Hoist", ["test"], "owner:test", None)
        os.environ["AGENT_BOARD_DB"] = str(self.db)
        try:
            self.assertEqual(board_module.main(["post", str(thread_id), "--as", "Kestrel", "hello"]), 0)
        finally:
            del os.environ["AGENT_BOARD_DB"]
        conn = self.board.connect()
        try:
            self.assertEqual([r[0] for r in conn.execute("SELECT author FROM entries")], ["kestrel"])
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
