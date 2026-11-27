"""Operate one Fabric-backed set of independently mounted domain workbenches."""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PORTS = {"a": 18441, "b": 18442, "c": 18443}
PROJECT_NAME = re.compile(r"grad-fabric-[a-f0-9]{12}")
ACCOUNTS = {"a": ("u", "buyer-password"), "b": ("admin", "admin-password"), "c": ("auditor", "auditor-password")}
TAGS = {side: f"grad-workbench-{side}:local" for side in ("frontend", "backend")}
CURL_IMAGE = "curlimages/curl@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69"


class OperationError(Exception):
    """An operator-facing failure whose message can be printed without credentials."""


def run(args, *, env=None, capture=False, **kwargs):
    if capture:
        kwargs["stdout"] = subprocess.PIPE
    proc = subprocess.run(args, check=True, text=True, env=os.environ | (env or {}), **kwargs)
    return proc.stdout


def network_project(instance):
    for line in (instance / "network.env").read_text().splitlines():
        key, _, value = line.partition("=")
        if key == "COMPOSE_PROJECT_NAME" and PROJECT_NAME.fullmatch(value):
            return value
    raise OperationError(f"invalid Fabric project in {instance}/network.env")


def build_images(*, publish_local=False):
    """Retain each local build by content so another checkout can still restart by image ID."""
    contexts = {
        "frontend": [ROOT / "web"],
        "backend": ["-f", ROOT / "infra/workbench/backend.Dockerfile", ROOT],
    }
    images = {}
    with tempfile.TemporaryDirectory() as tmp:
        for side, context in contexts.items():
            tag = TAGS[side]
            repository = tag.rsplit(":", 1)[0]
            iidfile = Path(tmp) / side
            run(["docker", "build", "--load", "--provenance=false", "--iidfile", iidfile, *context])
            image = iidfile.read_text().strip()
            if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
                raise OperationError(f"Docker did not return an image ID for {side}")
            run(["docker", "tag", image, f"{repository}:{image.replace(':', '-')}"])
            if publish_local:
                # Imported or older :local images may have no other tag in the image store.
                prior = run(["docker", "image", "ls", "--no-trunc", "--format", "{{.ID}}", tag], capture=True).strip()
                if prior and prior != image:
                    run(["docker", "tag", prior, f"{repository}:{prior.replace(':', '-')}"])
                run(["docker", "tag", image, tag])
            images[side] = image
    return images


@dataclass
class Workbench:
    project: str
    mounts: Path
    images: dict = field(default_factory=dict)
    owner: str = ""

    def compose(self, domain, *args, **kwargs):
        mount = self.mounts / domain
        env = {
            "WORKBENCH_CONFIG_DIR": str(mount),
            "WORKBENCH_UID": str(os.getuid()), "WORKBENCH_GID": str(os.getgid()),
            "WORKBENCH_DOMAIN": domain, "WORKBENCH_BROWSER_HOST": f"{domain}.localhost",
            "WORKBENCH_PORT": str(PORTS[domain]), "WORKBENCH_FABRIC_NETWORK": self.project + "_default",
            "GRAD_DEMO_OWNER": self.owner,
        }
        for side, tag in TAGS.items():
            var = f"WORKBENCH_{side.upper()}_IMAGE"
            env[var] = self.images.get(side) or os.environ.get(var) or tag
        if self.owner:
            env["WORKBENCH_BROWSER_UPSTREAM"] = "backend:8080"
        else:
            for var in ("WORKBENCH_UID", "WORKBENCH_GID"):
                env[var] = os.environ.get(var, env[var])
        return run(["docker", "compose", "-p", f"{self.project}-workbench-{domain}",
                    "-f", ROOT / "infra/workbench/compose.yaml", *args], env=env, **kwargs)

    def export_ca(self, domain):
        dest = self.mounts / domain / "browser-root.crt"
        # Keep interrupted copies outside the private mounts bound by the manifest.
        with tempfile.TemporaryDirectory(dir=self.mounts) as tmp:
            cert = Path(tmp) / "root.crt"
            self.compose(domain, "cp", "frontend:/data/caddy/pki/authorities/local/root.crt", str(cert), timeout=8)
            # A failed copy or malformed certificate must leave the previous trust anchor intact.
            run(["openssl", "x509", "-in", cert, "-noout"])
            if dest.exists() and dest.read_bytes() != cert.read_bytes():
                raise OperationError(f"{domain.upper()} browser CA differs from {dest}")
            cert.replace(dest)
        return dest

    def ready(self, domain):
        host = f"{domain}.localhost:{PORTS[domain]}"
        raw = run(["curl", "--silent", "--show-error", "--fail", "--max-time", "5", "--noproxy", "*",
                   "--cacert", self.mounts / domain / "browser-root.crt", "--resolve", f"{host}:127.0.0.1",
                   f"https://{host}/api/v1/health/ready"], capture=True)
        body = json.loads(raw)
        if not isinstance(body, dict) or body.get("ready") is not True or body.get("domainId") != domain.upper():
            raise OperationError(f"{domain.upper()} HTTPS readiness: expected ready=true and domainId={domain.upper()}")
        return body

    def wait_ready(self, domain, timeout=45):
        deadline = time.monotonic() + timeout
        exported = False
        while True:
            try:
                if not exported:
                    self.export_ca(domain)
                    exported = True
                return self.ready(domain)
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as err:
                if isinstance(err, subprocess.CalledProcessError) and exported and err.returncode in {51, 58, 60, 77}:
                    raise OperationError(f"{domain.upper()} HTTPS certificate validation failed ({err.returncode})") from None
                if time.monotonic() >= deadline:
                    stage = "HTTPS readiness" if exported else "browser CA export"
                    raise OperationError(f"{domain.upper()} {stage} timed out: {err}") from None
                time.sleep(1)

    def probe(self, run_id, key, order):
        if not run_id.strip() or not re.fullmatch("[a-f0-9]{64}", key):
            raise OperationError("probe requires a run ID and its 64-hex retry key")
        args = ["docker", "run", "--rm", "--read-only", "--user", f"{os.getuid()}:{os.getgid()}",
                "--network", self.project + "_default"]
        for name in ("internal-ca.crt", "internal.crt", "internal.key"):
            source = self.mounts / "a" / name
            if not source.is_file():
                raise OperationError(f"probe requires {source}")
            args.extend(["--volume", f"{source}:/certs/{name}:ro"])
        body = {"runId": run_id, "key": key, "order": order}
        run([*args, CURL_IMAGE, "--fail-with-body", "--silent", "--show-error", "--max-time", "60",
             "--cacert", "/certs/internal-ca.crt", "--cert", "/certs/internal.crt", "--key", "/certs/internal.key",
             "--json", json.dumps(body), "https://workbench-b:8081/internal/workbench/probe"])


def selected_workbench():
    demo = ROOT / ".local/demo"
    instance = Path(os.environ.get("FABRIC_INSTANCE", demo / "fabric")).resolve()
    mounts = Path(os.environ.get("WORKBENCH_ROOT", demo / "workbench")).resolve()
    project = network_project(instance)
    if instance == demo / "fabric" and mounts == demo / "workbench":
        manifest = json.loads((demo / "instance.json").read_text())
        if manifest["project"] != project or manifest["root"] != str(demo):
            raise OperationError("demo project and workbench directory do not match the instance record")
        return Workbench(project, mounts, manifest["images"], manifest["owner"])
    return Workbench(project, mounts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("images")
    compose = commands.add_parser("compose")
    compose.add_argument("domain", choices=PORTS)
    compose.add_argument("args", nargs=argparse.REMAINDER)
    for action in ("certs", "ready"):
        commands.add_parser(action).add_argument("domain", choices=PORTS, nargs="?")
    probe = commands.add_parser("probe")
    probe.add_argument("--run-id", required=True)
    probe.add_argument("--key", required=True)
    probe.add_argument("--order", action="store_true")
    args = parser.parse_args()
    if args.action == "images":
        print(json.dumps(build_images(publish_local=True)))
        return
    workbench = selected_workbench()
    if args.action == "compose":
        workbench.compose(args.domain, *args.args)
    elif args.action == "probe":
        workbench.probe(args.run_id, args.key, args.order)
    else:
        for domain in [args.domain] if args.domain else PORTS:
            if args.action == "certs":
                print(workbench.export_ca(domain))
            else:
                print(json.dumps(workbench.ready(domain)))


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as err:
        sys.exit(err.returncode or 1)
    except (OperationError, OSError, ValueError, KeyError) as err:
        sys.exit(str(err))
