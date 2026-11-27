"""Persist a local demo's identity and match it to the actual Docker resources."""

import fcntl
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import socket
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from ops import PORTS, PROJECT_NAME, OperationError, network_project, run

FABRIC_PORT = 18460
OWNER_LABEL = "io.grad.demo.owner"
PROJECT_LABEL = "com.docker.compose.project"


def plain_path(path):
    if path.is_symlink():
        raise OperationError(f"refusing symbolic link: {path}")
    return path


def atomic_json(path, value):
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as tmp:
        json.dump(value, tmp, indent=2)
        tmp.write("\n")
        tmp.flush()
        os.fsync(tmp.fileno())
    os.replace(tmp.name, path)


class DemoState:
    """Only the recorded absolute root and its random owner may adopt a project."""

    def __init__(self, repo):
        self.local = plain_path(repo / ".local")
        self.root = plain_path(self.local / "demo")
        self.fabric = self.root / "fabric"
        self.mounts = self.root / "workbench"
        self.record = self.root / "instance.json"
        self.removal = self.local / ".demo-removal.json"

    @contextmanager
    def lock(self):
        self.local.mkdir(mode=0o700, exist_ok=True)
        fd = os.open(self.local / ".demo.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "r+") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise OperationError("demo instance busy") from None
            yield

    def load(self):
        plain_path(self.root)
        if not self.root.exists():
            return None
        if not plain_path(self.record).is_file():
            raise OperationError(f"unowned directory: {self.root} (missing instance.json)")
        state = json.loads(self.record.read_text())
        if (not isinstance(state, dict) or state.get("root") != str(self.root)
                or not isinstance(state.get("owner"), str) or not re.fullmatch(r"[a-f0-9]{32}", state["owner"])
                or not isinstance(state.get("project"), str) or (state["project"] and not PROJECT_NAME.fullmatch(state["project"]))):
            raise OperationError(f"invalid demo ownership in {self.record}")
        for path in (self.fabric, self.mounts, self.root / ".prepare", self.fabric / "network.env"):
            plain_path(path)
        if self.mounts.exists():
            for domain in PORTS:
                plain_path(self.mounts / domain)
        env_file = self.fabric / "network.env"
        if env_file.exists() and state["project"]:
            if network_project(self.fabric) != state["project"]:
                raise OperationError("Fabric project differs from the demo record")
            if state.get("networkDigest") and hashlib.sha256(env_file.read_bytes()).hexdigest() != state["networkDigest"]:
                raise OperationError(f"Fabric settings differ from the registered {env_file}")
        return state

    def create(self, engine=""):
        state = dict(root=str(self.root), owner=secrets.token_hex(16), project="", networkDigest="", deploymentId="",
                     expiresAt=0, images={}, volumes={}, engine=engine, materials="", stage="new")
        with tempfile.TemporaryDirectory(dir=self.local) as tmp:
            atomic_json(Path(tmp) / self.record.name, state)
            Path(tmp).rename(self.root)
        return state

    def save(self, state, **changes):
        state.update(changes)
        atomic_json(self.record, state)

    def check_tree(self, state):
        # A mounted directory or a linked subtree can point outside the checkout.
        for directory, children, files in self.root.walk():
            for path in [directory, *(directory / name for name in children + files)]:
                if plain_path(path).is_mount():
                    raise OperationError(f"refusing mounted path: {path}")
        for path in self.root.iterdir():
            if path.is_dir() and path.name not in {"fabric", "workbench", ".prepare"}:
                raise OperationError(f"unowned directory: {path}")
        if state["deploymentId"]:
            for path in [self.fabric / "registry/deployment.json", *(self.mounts / d / "config.json" for d in PORTS)]:
                if path.exists() and json.loads(path.read_text()).get("deploymentId") != state["deploymentId"]:
                    raise OperationError(f"foreign deployment in {path}")

    def remove_files(self, state):
        # Keep proof outside the tree until rmtree (including its final rmdir) succeeds.
        st = self.root.stat()
        atomic_json(self.removal, dict(root=str(self.root), dev=st.st_dev, inode=st.st_ino,
                                       owner=state["owner"], project=state["project"], deploymentId=state["deploymentId"],
                                       engine=state.get("engine", "")))
        self.finish_removal()

    def finish_removal(self):
        receipt = json.loads(plain_path(self.removal).read_text())
        if receipt["root"] != str(self.root) or not re.fullmatch(r"[a-f0-9]{32}", receipt["owner"]):
            raise OperationError(f"invalid cleanup receipt: {self.removal}")
        if receipt["engine"]:
            docker_engine(receipt["engine"])
        if receipt["project"] and owned_resources(receipt, inventory()):
            raise OperationError("demo Docker resources still exist during local cleanup")
        if plain_path(self.root).exists():
            st = self.root.stat()
            if (st.st_dev, st.st_ino) != (receipt["dev"], receipt["inode"]):
                raise OperationError(f"directory replaced during cleanup: {self.root}")
            if self.record.exists() and self.load()["owner"] != receipt["owner"]:
                raise OperationError("demo ownership changed during cleanup")
            self.check_tree(receipt)
            shutil.rmtree(self.root)
        self.removal.unlink()

    def model_inputs(self, mounts):
        for domain in ("a", "b"):
            path = mounts / domain / "llm.env"
            key = path.with_name("model-api-key")
            for required in (path, key):
                if not required.is_file() or not required.read_bytes().strip():
                    raise OperationError(f"{domain.upper()} model configuration requires {required}")
            fields = {}
            for line in path.read_text().splitlines():
                name, sep, value = line.strip().removeprefix("export ").partition("=")
                if sep and not name.startswith("#"):
                    fields[name.strip()] = value.strip().strip("\"'")
            for name in ("LLM_PROVIDER", "LLM_MODEL", "LLM_BASE_URL"):
                if not fields.get(name):
                    raise OperationError(f"{domain.upper()} missing {name} in {path}")
            endpoint = urlsplit(fields["LLM_BASE_URL"])
            if fields["LLM_PROVIDER"].lower() not in {"openai", "anthropic"} or (
                    endpoint.scheme not in {"http", "https"} or not endpoint.hostname):
                raise OperationError(f"{domain.upper()} invalid model provider or endpoint in {path}")
            if {"LLM_API_KEY", "ANTHROPIC_AUTH_TOKEN"} & fields.keys():
                raise OperationError(f"{domain.upper()} put the model credential in {key}")
        return mounts


@dataclass(frozen=True)
class Resource:
    kind: str
    name: str
    project: str
    owner: str
    state: str
    ports: str
    service: str = ""

    def publishes(self, port):
        return any(int(first) <= port <= int(last or first)
                   for first, last in re.findall(r":(\d+)(?:-(\d+))?->", self.ports))


def inventory():
    """Read only names, ownership labels, running states and published ports."""
    resources = []
    labels = f'{{{{.Label "{PROJECT_LABEL}"}}}}|{{{{.Label "{OWNER_LABEL}"}}}}'
    for kind in ("container", "network", "volume"):
        args = ["docker", kind, "ls"]
        if kind == "container":
            args += ["-a", "--format", "{{.Names}}|" + labels + '|{{.State}}|{{.Ports}}|{{.Label "com.docker.compose.service"}}']
        else:
            args += ["--format", "{{.Name}}|" + labels + "||"]
        for line in run(args, capture=True).splitlines():
            resources.append(Resource(kind, *line.split("|")))
    return resources


def docker_engine(expected=""):
    engine = run(["docker", "info", "--format", "{{.ID}}"], capture=True).strip()
    if not engine or (expected and engine != expected):
        raise OperationError("Docker Engine differs from the one that owns this demo. Select the original Docker context.")
    return engine


def projects(project):
    return [*(f"{project}-workbench-{d}" for d in PORTS), project] if project else []


def owned_resources(state, resources):
    """Check both the physical name and the Compose labels before allowing mutations."""
    owned = []
    names = projects(state["project"])
    for obj in resources:
        named = next((p for p in names if obj.name.startswith(p + ("-" if obj.kind == "container" else "_"))), None)
        if named or obj.project in names or obj.owner == state["owner"]:
            if obj.project not in names or obj.owner != state["owner"] or (named and named != obj.project):
                raise OperationError(f"unowned {obj.kind} {obj.name} in demo project")
            owned.append(obj)
    return owned


def check_ports(resources, owned):
    for port in (*PORTS.values(), *range(FABRIC_PORT, FABRIC_PORT + 10)):
        publishers = [r for r in resources if r.state == "running" and r.publishes(port)]
        if publishers and all(r in owned for r in publishers):
            continue
        if publishers:
            raise OperationError(f"port {port} is already in use by {publishers[0].name}")
        with socket.socket() as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError as err:
                raise OperationError(f"port {port} unavailable: {err}") from None


def preflight(store, state):
    if platform.system() not in {"Darwin", "Linux"} or platform.machine() not in {"arm64", "aarch64"}:
        raise OperationError("demo requires an arm64 macOS or Linux host")
    for tool in ("docker", "go", "curl", "openssl", "shasum"):
        if not shutil.which(tool):
            raise OperationError(f"demo requires {tool}")
    store.model_inputs(store.mounts if store.mounts.exists() else store.local / "demo-config")
    run(["docker", "compose", "version"], capture=True)
    engine = docker_engine(state.get("engine", "") if state else "")
    resources = inventory()
    owned = owned_resources(state, resources) if state else []
    if state:
        volumes = {r.name for r in owned if r.kind == "volume"}
        for expected in state.get("volumes", {}).values():
            missing = set(expected) - volumes
            if missing:
                raise OperationError("missing retained volumes: " + ", ".join(sorted(missing)) +
                                     ". Restore the volumes or rebuild with mise run demo:clean && mise run demo:up")
    check_ports(resources, owned)
    return engine
