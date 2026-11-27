"""Check resolved Go package graphs, including test-only project dependencies."""

import subprocess


def dependencies(package, *, tests=False):
    # Exclude Go's synthetic test executables and annotated test variants.
    template = "{{if and (not .Standard) (not .ForTest)}}{{.ImportPath}}{{end}}"
    args = ["go", "list", "-deps", "-f", template]
    if tests:
        args.append("-test")
    names = subprocess.check_output([*args, package], text=True).splitlines()
    return {name for name in names if name and not name.endswith(".test")}


def check(module, allowed):
    packages = dependencies(f"grad/{module}/...", tests=True)
    forbidden = {p for p in packages if p.startswith("grad/") and
                 p.split("/")[1] not in allowed and p != "grad/protocol/registry"}
    if forbidden:
        raise SystemExit(f"{module} has forbidden dependencies: {', '.join(sorted(forbidden))}")


if __name__ == "__main__":
    check("protocol", {"protocol"})
    check("chaincode", {"chaincode"})
    check("platform", {"platform", "protocol"})
    registry = "grad/protocol/registry"
    external = dependencies(registry) - {registry}
    if external:
        raise SystemExit(f"{registry} requires non-standard packages: {', '.join(sorted(external))}")
