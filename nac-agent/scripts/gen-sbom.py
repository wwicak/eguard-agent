#!/usr/bin/env python3
"""Generate a CycloneDX 1.5 JSON SBOM from Go build info embedded in the binaries.

Usage: gen-sbom.py <go> <version> <out.json> <binary>...
Uses only `go version -m` output (what is actually linked), not go.mod guesses.
"""
import hashlib, json, subprocess, sys, uuid, datetime

LICENSES = {  # verified against docs/third-party-notices.md
    "github.com/StackExchange/wmi": "MIT",
    "github.com/go-ole/go-ole": "MIT",
    "go.etcd.io/bbolt": "MIT",
    "golang.org/x/sys": "BSD-3-Clause",
}

def main():
    go, version, out, bins = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
    comps, toolchain = {}, None
    files = []
    for b in bins:
        info = subprocess.run([go, "version", "-m", b], capture_output=True, text=True, check=True).stdout
        for line in info.splitlines():
            f = line.strip().split("\t")
            if line.startswith(b + ":"):
                toolchain = line.split(":", 1)[1].strip()
            if f[0] == "dep":
                name, ver = f[1], f[2]
                comps[(name, ver)] = f[3] if len(f) > 3 else ""
        files.append({"type": "file", "name": b.split("/")[-1],
                      "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(open(b, "rb").read()).hexdigest()}]})
    components = [{
        "type": "library", "name": n, "version": v,
        "purl": f"pkg:golang/{n}@{v}",
        "licenses": [{"license": {"id": LICENSES.get(n, "NOASSERTION")}}] if n in LICENSES else [{"license": {"name": "NOASSERTION"}}],
        "hashes": [{"alg": "SHA-256", "content": h}] if False else [],
        "properties": [{"name": "go:module-sum", "value": h}],
    } for (n, v), h in sorted(comps.items())]
    components.append({"type": "framework", "name": "golang-toolchain", "version": toolchain or "unknown",
                       "licenses": [{"license": {"id": "BSD-3-Clause"}}]})
    for c in components:
        if not c.get("hashes"):
            c.pop("hashes", None)
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
            "component": {"type": "application", "name": "eguard-nac-agent", "version": version,
                          "properties": [{"name": "eguard:build-label", "value": "TEST-UNSIGNED"}]},
        },
        "components": components + files,
    }
    json.dump(doc, open(out, "w"), indent=2)
    print(f"sbom: {len(comps)} modules, {len(files)} files -> {out}")

main()
