import io
import json
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from demo import Demo, logs, main, status
from demo_state import DemoState, OperationError, Resource, check_ports, docker_engine, owned_resources, preflight, projects
from ops import ACCOUNTS, PORTS


class DemoTest(unittest.TestCase):
    def setUp(self):
        self.output = self.enterContext(redirect_stdout(io.StringIO()))
        self.errors = self.enterContext(redirect_stderr(io.StringIO()))
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = DemoState(Path(tmp.name).resolve())
        self.config = self.store.local / "demo-config"
        for domain in "ab":
            path = self.config / domain
            path.mkdir(parents=True)
            (path / "llm.env").write_text("LLM_PROVIDER=openai\nLLM_MODEL=test\nLLM_BASE_URL=https://model.test/v1\n")
            (path / "model-api-key").write_text("private-test-value")


class PreflightTests(DemoTest):
    def test_missing_model_file_precedes_any_service(self):
        (self.config / "b/model-api-key").unlink()
        with patch("demo_state.platform.machine", return_value="arm64"), patch("demo_state.shutil.which", return_value="/tool"), patch("demo_state.run") as invoke:
            with self.assertRaisesRegex(OperationError, "B .*model-api-key"):
                preflight(self.store, None)
            invoke.assert_not_called()
        self.assertFalse(self.store.root.exists())

    def test_published_and_host_ports_are_checked_before_allocation(self):
        other = Resource("container", "another", "other", "", "running", "127.0.0.1:18440-18442->8443/tcp")
        with self.assertRaisesRegex(OperationError, "18441.*another"):
            check_ports([other], [])
        with patch("demo_state.socket.socket") as sock:
            sock.return_value.__enter__.return_value.bind.side_effect = OSError("occupied")
            with self.assertRaisesRegex(OperationError, "18441.*occupied"):
                check_ports([], [])
        self.assertFalse(self.store.root.exists())

    def test_lock_ownership_and_atomic_record(self):
        with self.store.lock():
            with self.assertRaisesRegex(OperationError, "busy"), self.store.lock():
                self.fail("concurrent mutation acquired the lock")
            state = self.store.create()
        with self.store.lock():
            self.assertEqual(self.store.load(), state)
            self.store.save(state, project="grad-fabric-0123456789ab")
            self.assertEqual(self.store.load()["project"], state["project"])
        self.store.record.write_text(json.dumps(state | {"root": "/elsewhere"}))
        with self.assertRaisesRegex(OperationError, "ownership"):
            self.store.load()
        self.store.record.unlink()
        with self.assertRaisesRegex(OperationError, "unowned"):
            self.store.load()

    def test_compose_project_collision_is_not_adopted(self):
        project = "grad-fabric-0123456789ab"
        state = {"owner": "ours", "project": project}
        foreign = Resource("volume", project + "_db", project, "foreign", "", "")
        with self.assertRaisesRegex(OperationError, foreign.name):
            owned_resources(state, [foreign])

    def test_engine_switch_and_missing_retained_volume(self):
        with patch("demo_state.run", return_value="other-engine"), self.assertRaisesRegex(OperationError, "original Docker context"):
            docker_engine("bound-engine")
        state = self.store.create()
        state["volumes"] = {"a": ["lost-database"]}
        with patch("demo_state.platform.machine", return_value="arm64"), patch("demo_state.shutil.which", return_value="/tool"), patch("demo_state.run"), patch("demo_state.inventory", return_value=[]):
            with self.assertRaisesRegex(OperationError, "missing retained volumes: lost-database"):
                preflight(self.store, state)


class QueryTests(DemoTest):
    def test_empty_queries_do_not_create_anything(self):
        for action in ("status", "logs"):
            with patch("demo.ROOT", self.store.local.parent), patch("sys.argv", ["demo", action]), patch("demo.inventory") as inspect:
                main()
                inspect.assert_not_called()
        self.assertFalse(self.store.root.exists())
        self.assertFalse((self.store.local / ".demo.lock").exists())
        self.assertIn("not created", self.output.getvalue())

    def test_partial_domain_diagnostics_and_secret_redaction(self):
        state = self.store.create()
        self.store.save(state, project="grad-fabric-0123456789ab", stage="B HTTPS ready")
        demo = Demo(self.store, state)
        project = state["project"] + "-workbench-b"
        items = [Resource("container", project + "-frontend-1", project, state["owner"], "running", "", "frontend")]
        with patch("demo.Workbench.ready", side_effect=OperationError("certificate validation failed")):
            self.assertEqual(status(demo, items), "partial")
        with patch("demo.run", return_value="failed to mount\nprivate-test-value\nAuthorization: Bearer token-value") as read:
            logs(demo, items, "b", "frontend", 4)
            self.assertIn(items[0].name, read.call_args.args[0])
        output = self.output.getvalue()
        self.assertIn("B HTTPS ready", output)
        self.assertIn("certificate validation failed", output)
        self.assertIn("failed to mount", output)
        self.assertNotIn("private-test-value", output)
        self.assertNotIn("token-value", output)


class CleanupTests(DemoTest):
    def setUp(self):
        super().setUp()
        self.state = self.store.create()
        self.project = "grad-fabric-0123456789ab"
        self.store.save(self.state, project=self.project)
        self.demo = Demo(self.store, self.state)
        self.foreign = Resource("volume", "other_test_db", "other", "independent", "", "")
        self.objects = [self.foreign]
        for project in projects(self.project):
            self.objects += [Resource("container", project + "-db-1", project, self.state["owner"], "running", ""),
                             Resource("network", project + "_default", project, self.state["owner"], "", ""),
                             Resource("volume", project + "_db", project, self.state["owner"], "", "")]
        self.removed = []
        self.fail = ""
        for module in ("demo", "demo_state"):
            self.enterContext(patch(module + ".inventory", side_effect=lambda: list(self.objects)))
        self.enterContext(patch("demo.run", side_effect=self.docker))

    def docker(self, args):
        if "rm" in args:
            name = args[-1]
            if self.fail == name:
                raise OperationError(f"failed to remove {name}")
            self.removed.append(name)
            self.objects = [o for o in self.objects if o.name != name]

    def test_down_then_clean_and_repeated_clean_preserve_external_inputs(self):
        self.demo.stop(False)
        self.assertEqual(self.store.load()["stage"], "stopped")
        self.assertTrue(all(r.kind == "volume" for r in self.objects))
        self.assertEqual(self.removed[-1], self.project + "_default")
        self.demo.stop(True)
        with patch("demo.ROOT", self.store.local.parent), patch("sys.argv", ["demo", "clean"]):
            main()
        self.assertFalse(self.store.root.exists())
        self.assertTrue((self.config / "a/model-api-key").is_file())
        self.assertEqual(self.objects, [self.foreign])

    def test_clean_running_and_retry_partial_removal(self):
        self.fail = projects(self.project)[1] + "_db"
        with self.assertRaisesRegex(OperationError, self.fail):
            self.demo.stop(True)
        self.assertTrue(self.store.record.is_file())
        self.fail = ""
        Demo(self.store, self.store.load()).stop(True)
        self.assertFalse(self.store.root.exists())
        self.assertEqual(self.objects, [self.foreign])
        self.assertEqual(len(self.removed), len(set(self.removed)))

    def test_symlink_is_rejected_before_any_resource_is_removed(self):
        self.store.fabric.symlink_to(self.config, target_is_directory=True)
        with self.assertRaisesRegex(OperationError, "symbolic link"):
            self.demo.stop(True)
        self.assertFalse(self.removed)
        self.assertTrue((self.config / "b/model-api-key").is_file())

    def test_interrupted_local_removal_can_resume_without_manifest(self):
        def interrupt(path):
            self.store.record.unlink()
            raise OSError("interrupted local deletion")
        with patch("demo_state.shutil.rmtree", side_effect=interrupt), self.assertRaisesRegex(OSError, "interrupted"):
            self.demo.stop(True)
        self.assertTrue(self.store.removal.is_file())
        self.store.finish_removal()
        self.assertFalse(self.store.root.exists())
        self.assertFalse(self.store.removal.exists())


class RecoveryTests(DemoTest):
    def setUp(self):
        super().setUp()
        self.state = self.store.create()
        self.demo = Demo(self.store, self.state)
        self.project = "grad-fabric-0123456789ab"
        self.deployment = "e" * 64
        self.calls = []
        self.expiry = int(time.time()) + 86400
        self.interrupt = False
        self.mock("demo.inventory", return_value=[
            Resource("volume", p + "_db", p, self.state["owner"], "", "") for p in projects(self.project)])
        self.mock("demo.Demo.fabric", side_effect=self.fabric)
        self.mock("demo.Demo.ledger", side_effect=self.ledger)
        self.mock("demo.run", side_effect=self.prepare)
        self.images = self.mock("demo.build_images", return_value={"frontend": "sha256:" + "a" * 64,
                                                                   "backend": "sha256:" + "b" * 64})
        for action in ("compose", "export_ca", "ready"):
            self.mock(f"demo.Workbench.{action}")

    def mock(self, name, **kwargs):
        return self.enterContext(patch(name, **kwargs))

    def fabric(self, action):
        self.calls.append(action)
        if action == "init":
            self.store.fabric.mkdir()
            (self.store.fabric / "network.env").write_text("COMPOSE_PROJECT_NAME=" + self.project)

    def ledger(self, action):
        self.calls.append(action)
        registry = self.store.fabric / "registry"
        if action == "deploy":
            registry.mkdir()
            (registry / "deployment.json").write_text(json.dumps({"deploymentId": self.deployment}))
        if action == "seed":
            fixtures = {"deploymentId": self.deployment, "credentials": {"U": {"exp": self.expiry}}}
            (registry / "fixtures.json").write_text(json.dumps(fixtures))
            report = dict(deploymentId=self.deployment, operations=[dict(status="CONFIRMED", commit={"validationCode": "VALID"})])
            (registry / "seed.json").write_text(json.dumps(report))

    def prepare(self, args, **kwargs):
        if "prepare" not in args:
            return
        self.calls.append("prepare")
        output = args[-1]
        for d, (_, password) in ACCOUNTS.items():
            mount = output / d
            mount.mkdir(parents=True)
            (mount / "config.json").write_text(json.dumps({"deploymentId": self.deployment, "domainId": d.upper()}))
            for name in ("admin-password", password, "postgres-password", "internal-ca.crt", "internal.crt", "internal.key"):
                (mount / name).write_text("private-" + str(self.calls.count("prepare")))
            if self.interrupt:
                raise OperationError("interrupted")

    def test_second_up_reuses_identity_materials_and_images(self):
        self.demo.up()
        before = self.store.load()
        Demo(self.store, self.store.load()).up()
        self.assertEqual(self.store.load(), before)
        self.assertEqual(self.calls.count("prepare"), 1)
        self.assertEqual(self.calls.count("seed"), 1)
        self.assertEqual(self.calls.count("check"), 2)
        self.images.assert_called_once()
        self.assertEqual((self.store.mounts / "a/model-api-key").stat().st_mode & 0o777, 0o600)
        self.assertFalse((self.store.mounts / "c/model-api-key").exists())

    def test_partial_prepare_retries_before_publishing(self):
        self.interrupt = True
        with self.assertRaisesRegex(OperationError, "interrupted"):
            self.demo.up()
        self.assertFalse(self.store.mounts.exists())
        self.assertEqual(self.store.load()["stage"], "workbench prepare")
        self.interrupt = False
        Demo(self.store, self.store.load()).up()
        for d in PORTS:
            self.assertTrue((self.store.mounts / d / "internal.key").is_file())
        self.assertEqual(self.calls.count("deploy"), 1)
        self.assertEqual(self.calls.count("prepare"), 2)

    def test_expired_fixture_preserves_original_instance(self):
        self.demo.up()
        before = self.store.load()
        with patch("demo.time.time", return_value=self.expiry), self.assertRaisesRegex(OperationError, "expired at .*demo:clean"):
            self.demo.up()
        self.assertEqual(self.store.load(), before)
        self.assertEqual(self.calls.count("up"), 1)
