"""Manage the repository's local three-domain procurement demo."""

import argparse
import hashlib
import json
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

from demo_state import FABRIC_PORT, DemoState, docker_engine, inventory, owned_resources, plain_path, preflight, projects
from ops import ACCOUNTS, PORTS, ROOT, TAGS, OperationError, Workbench, build_images, network_project, run

REBUILD = "mise run demo:clean && mise run demo:up"


def utc(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="seconds")


def check_expiry(expires):
    if expires and time.time() >= expires:
        raise OperationError(f"demo fixtures expired at {utc(expires)}. To rebuild: {REBUILD}")


def read_record(path):
    return json.loads(plain_path(path).read_text())


def material_digest(mounts, deployment):
    """Bind the published private mounts, excluding Caddy's subsequently exported public roots."""
    digest = hashlib.sha256()
    for domain, (_, password) in ACCOUNTS.items():
        mount = plain_path(mounts / domain)
        config = read_record(mount / "config.json")
        if config["domainId"] != domain.upper() or config["deploymentId"] != deployment:
            raise OperationError(f"{domain.upper()} private mount belongs to another deployment")
        for name in ("admin-password", password, "postgres-password", "internal-ca.crt", "internal.crt", "internal.key"):
            if not plain_path(mount / name).is_file():
                raise OperationError(f"{domain.upper()} missing private material: {name}")
        for path in sorted(mount.rglob("*")):
            if plain_path(path).is_dir() or path == mount / "browser-root.crt":
                continue
            digest.update(path.relative_to(mounts).as_posix().encode() + b"\0")
            with path.open("rb") as stream:
                digest.update(hashlib.file_digest(stream, "sha256").digest())
    return digest.hexdigest()


class Demo:
    def __init__(self, store, state):
        self.store = store
        self.state = state

    def stage(self, name):
        self.store.save(self.state, stage=name, lastError="")
        print(name, file=sys.stderr, flush=True)

    def fabric(self, *args, **kwargs):
        env = {"FABRIC_INSTANCE": str(self.store.fabric), "FABRIC_PORT": str(FABRIC_PORT),
               "GRAD_DEMO_OWNER": self.state["owner"]}
        return run(["sh", ROOT / "infra/fabric/network.sh", *args], env=env, **kwargs)

    def ledger(self, action):
        run(["go", "run", "grad/platform/cmd/ledgerctl", action, "--dir", self.store.fabric],
            env={"GRAD_DEMO_OWNER": self.state["owner"]}, stdout=subprocess.DEVNULL)

    def binding(self):
        return Workbench(self.state["project"], self.store.mounts, self.state["images"], self.state["owner"])

    def bind_volumes(self, project):
        bindings = self.state.get("volumes", {})
        if project in bindings:
            return
        names = sorted(r.name for r in owned_resources(self.state, inventory()) if r.project == project and r.kind == "volume")
        if not names:
            raise OperationError(f"missing persistent volumes for {project}")
        self.store.save(self.state, volumes=bindings | {project: names})

    def check_fixture(self):
        path = self.store.fabric / "registry/fixtures.json"
        if not path.exists():
            if self.state["expiresAt"]:
                raise OperationError(f"recorded fixtures are missing. To rebuild: {REBUILD}")
            return
        fixture = read_record(path)
        if fixture["deploymentId"] != self.state["deploymentId"]:
            raise OperationError("fixture deployment differs from demo deployment")
        expiry = min(int(v["exp"]) for v in fixture["credentials"].values())
        if self.state["expiresAt"] and self.state["expiresAt"] != expiry:
            raise OperationError("fixture expiry differs from instance record")
        check_expiry(expiry)
        self.store.save(self.state, expiresAt=expiry)

    def prepare_mounts(self):
        store, state = self.store, self.state
        pending = plain_path(store.root / ".prepare")
        if not state["materials"]:
            if store.mounts.exists():
                raise OperationError("published workbench mounts have no recorded identity")
            if pending.exists():
                shutil.rmtree(pending)
            run(["go", "run", "grad/platform/cmd/workbench", "prepare",
                 "--fabric", store.fabric, "--output", pending])
            inputs = store.model_inputs(store.local / "demo-config")
            for domain in ("a", "b"):
                for name in ("llm.env", "model-api-key"):
                    dest = pending / domain / name
                    shutil.copyfile(inputs / domain / name, dest)
                    dest.chmod(0o600)
            store.model_inputs(pending)
            store.save(state, materials=material_digest(pending, state["deploymentId"]))
        location = store.mounts if store.mounts.exists() else pending
        if material_digest(location, state["deploymentId"]) != state["materials"]:
            raise OperationError(f"prepared mount digest differs from the demo record. To rebuild: {REBUILD}")
        if location == pending:
            pending.rename(store.mounts)

    def up(self):
        store, state = self.store, self.state
        registry = plain_path(store.fabric / "registry")
        if state["stage"].startswith("clean"):
            raise OperationError("cleanup is incomplete. Resume with mise run demo:clean")
        check_expiry(state["expiresAt"])
        self.stage("fabric init")
        if not (store.fabric / "network.env").is_file():
            if store.fabric.exists() or state["project"]:
                raise OperationError(f"incomplete Fabric initialization. To rebuild: {REBUILD}")
            self.fabric("init")
        project = network_project(store.fabric)
        if state["project"] and project != state["project"]:
            raise OperationError("Fabric project differs from the instance record")
        store.save(state, project=project, networkDigest=hashlib.sha256((store.fabric / "network.env").read_bytes()).hexdigest())
        # Check the generated namespace before any command may create Docker objects in it.
        owned_resources(state, inventory())
        deployment = registry / "deployment.json"
        if state["deploymentId"] and (not deployment.is_file() or read_record(deployment)["deploymentId"] != state["deploymentId"]):
            raise OperationError(f"Fabric deployment differs from the instance record. To rebuild: {REBUILD}")
        if state["deploymentId"]:
            self.check_fixture()
        self.stage("fabric up")
        self.fabric("up")
        self.stage("ledger deploy")
        if not deployment.exists():
            self.ledger("deploy")
        identity = read_record(deployment)["deploymentId"]
        if not re.fullmatch(r"[a-f0-9]{64}", identity):
            raise OperationError("invalid Fabric deployment identifier")
        store.save(state, deploymentId=identity)
        self.check_fixture()
        self.stage("ledger seed")
        seed = registry / "seed.json"
        if not seed.exists():
            self.ledger("seed")
        report = read_record(seed)
        if (report["deploymentId"] != identity or not report["operations"] or
                any(op["status"] != "CONFIRMED" or op["commit"]["validationCode"] != "VALID" for op in report["operations"])):
            raise OperationError(f"incomplete or mismatched seed commits. To rebuild: {REBUILD}")
        self.check_fixture()
        self.stage("ledger check")
        self.ledger("check")
        self.bind_volumes(project)
        self.stage("workbench prepare")
        self.prepare_mounts()
        self.stage("workbench images")
        if not state["images"]:
            store.save(state, images=build_images())
        for side in TAGS:
            image = state["images"][side]
            if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
                raise OperationError(f"invalid recorded {side} image")
            run(["docker", "image", "inspect", "--format", "{{.Id}}", image], capture=True)
        wb = self.binding()
        for domain in PORTS:
            self.stage(f"{domain.upper()} compose up")
            wb.compose(domain, "up", "-d", "--wait", "--wait-timeout", "180")
            self.stage(f"{domain.upper()} HTTPS ready")
            wb.wait_ready(domain)
            self.bind_volumes(f"{project}-workbench-{domain}")
        self.stage("ready")
        print_access(store, state)

    def stop(self, clean):
        store, state = self.store, self.state
        if clean:
            store.check_tree(state)
        objects = owned_resources(state, inventory()) if state["project"] else []
        action = "clean" if clean else "down"
        for project in projects(state["project"]):
            members = [obj for obj in objects if obj.project == project]
            if not members:
                continue
            self.stage(f"{action} {project}")
            # Stop consumers before Fabric. Address the owned domain containers directly
            # so a missing model input or an incomplete mount cannot prevent shutdown.
            if project == state["project"] and (store.fabric / "network.env").is_file():
                self.fabric("down")
                members = [r for r in owned_resources(state, inventory()) if r.project == project]
            for obj in members:
                if obj.kind == "container":
                    if obj.state == "running":
                        run(["docker", "stop", obj.name])
                    run(["docker", "container", "rm", *(["-v"] if clean else []), obj.name])
            for obj in members:
                if obj.kind == "network" or (clean and obj.kind == "volume"):
                    run(["docker", obj.kind, "rm", obj.name])
        if state["project"]:
            remaining = [r.name for r in owned_resources(state, inventory()) if clean or r.kind != "volume"]
            if remaining:
                raise OperationError("remaining demo resources: " + ", ".join(remaining))
        if clean:
            self.stage("clean files")
            store.remove_files(state)
            print("Demo cleaned")
        else:
            self.stage("stopped")
            print("Demo stopped")


def print_access(store, state):
    print(f"Deployment {state['deploymentId']}, fixtures expire {utc(state['expiresAt'])}")
    for domain, (account, password) in ACCOUNTS.items():
        mount = store.mounts / domain
        print(f"https://{domain}.localhost:{PORTS[domain]}  account {account}  password file {mount / password}")
        print(f"Trust the public CA in your demo browser: {mount / 'browser-root.crt'}")


def status(demo, objects):
    state = demo.state
    print(f"Last stage: {state['stage']}")
    if state.get("lastError"):
        print(state["lastError"])
    if state["expiresAt"]:
        label = "expired" if time.time() >= state["expiresAt"] else "expire"
        print(f"Fixtures {label}: {utc(state['expiresAt'])}")
    if state["deploymentId"]:
        print(f"Deployment: {state['deploymentId']}")
    running = [r for r in objects if r.state == "running"]
    fabric = [r for r in running if r.project == state["project"]]
    print(f"Fabric: {len(fabric)} running containers")
    ready = []
    for domain in PORTS:
        project = f"{state['project']}-workbench-{domain}"
        services = {r.service for r in running if r.project == project}
        detail = "running: " + ", ".join(sorted(services)) if services else "stopped or not started"
        if "frontend" in services:
            try:
                demo.binding().ready(domain)
                ready.append(domain)
                detail = "ready"
            except (OperationError, OSError, ValueError, subprocess.SubprocessError) as err:
                detail = f"HTTPS check failed: {err}"
        print(f"{domain.upper()} https://{domain}.localhost:{PORTS[domain]} {detail}")
    if fabric and len(ready) == len(PORTS):
        return "ready"
    if not running and state["stage"] == "stopped":
        return "stopped"
    return "partial"


def redact_logs(output, store):
    # Logs may contain multiple PEM lines or echo an unlabelled configured credential.
    output = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|\Z)",
                    "[redacted private key]", output, flags=re.S)
    for parent in (store.mounts, store.local / "demo-config"):
        for domain in PORTS:
            mount = parent / domain
            for name in ("admin-password", "buyer-password", "auditor-password", "postgres-password", "model-api-key"):
                path = mount / name
                if path.is_file():
                    value = path.read_text().strip()
                    if value:
                        output = output.replace(value, "[redacted]")
    password = store.fabric / "view-password"
    if password.is_file() and (value := password.read_text().strip()):
        output = output.replace(value, "[redacted]")
    sensitive = re.compile(r"authorization[\"' :\t]|set-cookie|api[_-]?key|password|bearer\s|session[_-]?token", re.I)
    return "\n".join("[redacted log line]" if sensitive.search(line) else line for line in output.splitlines())


def logs(demo, objects, target, service, tail):
    project = demo.state["project"]
    selected = projects(project) if target is None else [project if target == "fabric" else f"{project}-workbench-{target}"]
    containers = [r for r in objects if r.kind == "container" and r.project in selected and
                  (service is None or r.service == service)]
    print(f"Last stage: {demo.state['stage']}")
    if demo.state.get("lastError"):
        print(demo.state["lastError"])
    if not containers:
        print("No matching containers")
    for container in containers:
        print(container.name)
        raw = run(["docker", "logs", "--tail", str(tail), container.name], capture=True, stderr=subprocess.STDOUT)
        print(redact_logs(raw, demo.store))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    for action in ("up", "down", "clean", "status"):
        commands.add_parser(action)
    query = commands.add_parser("logs")
    query.add_argument("target", choices=[*PORTS, "fabric"], nargs="?")
    query.add_argument("service", nargs="?")
    query.add_argument("--tail", type=int, default=60)
    args = parser.parse_args()
    store = DemoState(ROOT)
    if args.action in ("status", "logs"):
        if plain_path(store.removal).exists():
            print("Local cleanup in progress. Resume with mise run demo:clean")
            return
        state = store.load()
        if state is None:
            print("Demo not created")
            return
        demo = Demo(store, state)
        if state.get("engine"):
            docker_engine(state["engine"])
        objects = owned_resources(state, inventory()) if state["project"] else []
        if args.action == "status":
            print("Demo " + status(demo, objects))
        else:
            logs(demo, objects, args.target, args.service, args.tail)
        return
    with store.lock():
        if plain_path(store.removal).exists():
            if args.action != "clean":
                raise OperationError("local cleanup incomplete. Resume with mise run demo:clean")
            store.finish_removal()
            print("Demo cleaned")
            return
        state = store.load()
        if args.action == "up":
            engine = preflight(store, state)
            state = state or store.create(engine)
        elif state is None:
            print("Demo not created")
            return
        elif args.action == "down" and state["stage"].startswith("clean"):
            raise OperationError("cleanup is incomplete. Resume with mise run demo:clean")
        elif state.get("engine"):
            docker_engine(state["engine"])
        demo = Demo(store, state)
        try:
            if args.action == "up":
                demo.up()
            else:
                demo.stop(clean=args.action == "clean")
        except (OSError, ValueError, KeyError, OperationError, subprocess.CalledProcessError) as err:
            reason = str(err)
            if isinstance(err, subprocess.CalledProcessError):
                reason = f"{shlex.join(map(str, err.cmd))} exited with code {err.returncode}"
            detail = f"{demo.state['stage']}: {reason}"
            if store.record.is_file() and not store.removal.exists():
                # Only persist errors from the fixed orchestration commands, never service logs.
                store.save(state, lastError=detail)
            raise OperationError(detail) from None


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, OperationError, subprocess.CalledProcessError) as err:
        sys.exit(str(err))
