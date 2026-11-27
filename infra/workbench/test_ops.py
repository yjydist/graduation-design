import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ops import PORTS, TAGS, OperationError, Workbench, build_images


class WorkbenchTests(unittest.TestCase):
    def test_image_ids_survive_later_builds_and_manual_retagging(self):
        previous = "sha256:" + "c" * 64
        images = {side: "sha256:" + digit * 64 for side, digit in (("frontend", "a"), ("backend", "b"))}
        def docker(args, **kwargs):
            if args[1] == "build":
                iidfile = args[args.index("--iidfile") + 1]
                iidfile.write_text(images[iidfile.name])
            elif args[1:3] == ["image", "ls"]:
                return previous

        for publish in (False, True):
            with self.subTest(publish=publish), patch("ops.run", side_effect=docker) as invoke:
                self.assertEqual(build_images(publish_local=publish), images)
                tags = [c.args[0][2:] for c in invoke.call_args_list if c.args[0][1] == "tag"]
                for side, tag in TAGS.items():
                    repo = tag.split(":")[0]
                    image = images[side]
                    self.assertIn([image, repo + ":" + image.replace(":", "-")], tags)
                    if publish:
                        retained = [previous, repo + ":" + previous.replace(":", "-")]
                        self.assertLess(tags.index(retained), tags.index([image, tag]))
                    else:
                        self.assertNotIn([image, tag], tags)

    def test_https_requires_target_domain_and_true_ready(self):
        wb = Workbench("test", Path("/mounts"))
        for body in ('{"domainId":"B","ready":true}', '{"domainId":"A","ready":false}'):
            with patch("ops.run", return_value=body) as curl, self.assertRaisesRegex(OperationError, "A HTTPS"):
                wb.ready("a")
            args = curl.call_args.args[0]
            self.assertEqual(args[args.index("--cacert") + 1], Path("/mounts/a/browser-root.crt"))
            self.assertIn("a.localhost:18441:127.0.0.1", args)

    def test_timeout_and_certificate_failure_identify_domain(self):
        wb = Workbench("test", Path("/mounts"))
        for code, reason in ((28, "timed out"), (60, "certificate validation failed")):
            with patch.object(wb, "export_ca"), patch.object(wb, "ready", side_effect=subprocess.CalledProcessError(code, "curl")):
                with self.assertRaisesRegex(OperationError, "B HTTPS.*" + reason):
                    wb.wait_ready("b", timeout=0)

    def test_probe_uses_callers_binding_and_only_a_transport_material(self):
        with tempfile.TemporaryDirectory() as tmp:
            mounts = Path(tmp)
            (mounts / "a").mkdir()
            for name in ("internal-ca.crt", "internal.crt", "internal.key"):
                (mounts / "a" / name).touch()
            with patch("ops.run") as invoke:
                Workbench("test", mounts).probe("run with spaces", "a" * 64, True)
            args = invoke.call_args.args[0]
            self.assertEqual(json.loads(args[args.index("--json") + 1]),
                             {"runId": "run with spaces", "key": "a" * 64, "order": True})
            self.assertEqual(args[args.index("--network") + 1], "test_default")
            self.assertEqual(args.count("--volume"), 3)

    def test_compose_binds_one_domain_per_project(self):
        images = {"frontend": "sha256:" + "a" * 64, "backend": "sha256:" + "b" * 64}
        wb = Workbench("grad-fabric-0123456789ab", Path("/private/domain mounts"), images, "owner")
        for domain in PORTS:
            with self.subTest(domain=domain), patch("ops.run") as invoke:
                wb.compose(domain, "logs", "backend")
                args = invoke.call_args.args[0]
                self.assertIn(f"{wb.project}-workbench-{domain}", args)
                env = invoke.call_args.kwargs["env"]
                self.assertEqual(env["WORKBENCH_CONFIG_DIR"], str(wb.mounts / domain))
                self.assertEqual(env["WORKBENCH_FABRIC_NETWORK"], wb.project + "_default")
                for name, ref in images.items():
                    self.assertEqual(env[f"WORKBENCH_{name.upper()}_IMAGE"], ref)
