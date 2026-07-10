#!/usr/bin/env python3
# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  data/relevance_build.py — build packs/relevance/role-groups.yaml from a
#  grounded seed. Standalone tooling (Relevance layer). No engine imports.
# =============================================================================
"""Emit the role-group catalog that lets promotion scope CVEs to what matters.

Relevance = SCOPE, not severity. An AI-serving host's real surface is the serving
stack, the isolation boundary, and the crypto/network/auth exposure — NOT every
installed package. This catalog is what routes the firefox/chromium/desktop flood
to catalog instead of drowning the report.

AGNOSTIC by construction: role-groups key on upstream PROJECT-name patterns
(openssl/libssl both hit crypto; kernel/linux-image both hit kernel), stable across
Debian/RHEL/Alpine/Arch; roles are defined by what they DO, never by vendor/distro.
GROUNDED by construction: every technique id is validated against the knowledge
graph (dropped if absent or mistyped) and every D3FEND artifact IRI is validated
against the extracted attack-artifact map (can't anchor to an artifact that isn't
real). Nothing ungrounded reaches the emitted file. Re-runnable; edit the seed and
regenerate, or hand-edit the emitted YAML.
"""
from __future__ import annotations
import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAP = ROOT / "packs/relevance/attack-artifact-map.json"
NODES = ROOT / "build/graph/nodes.json"
OUT = ROOT / "packs/relevance/role-groups.yaml"
DAO = "http://d3fend.mitre.org/ontologies/d3fend.owl#"

# (tier, name, [artifact-class candidates -> first present in map wins], patterns, techniques)
SEED = [
 ("isolation_boundary","container_runtime",["ContainerImage","ContainerRuntime","Container"],
  ["containerd","runc","docker","podman","cri-o","crio","lxc","lxd","buildah","nerdctl"],
  ["T1610","T1611","T1613","T1609"]),
 ("isolation_boundary","hypervisor",["VirtualizationSoftware","Hypervisor"],
  ["qemu","kvm","libvirt","xen","virtualbox","virt-manager","virt-what","ovmf"],
  ["T1611","T1497"]),
 ("isolation_boundary","kernel",["Kernel","OperatingSystemKernel","KernelModule"],
  ["linux-image","linux-headers","linux-modules","kernel","linux-lts","linux-kbuild","kmod"],
  ["T1611","T1547.006","T1014","T1601"]),
 ("isolation_boundary","confinement",["MandatoryAccessControlSystem","AccessControlConfiguration","OperatingSystem","Kernel"],
  ["apparmor","selinux","libselinux","seccomp","libseccomp","policycoreutils"],
  ["T1548","T1553"]),
 ("isolation_boundary","network_egress",["OutboundInternetNetworkTraffic","InternetNetworkTraffic","NetworkTraffic"],
  ["iptables","nftables","nft","ufw","firewalld","netfilter","conntrack"],
  ["T1071","T1041","T1048","T1090"]),
 ("serving_stack","model_server",["WebServerApplication","WebServer","ServiceApplication","ServerApplication","Software"],
  ["vllm","triton","tgi","text-generation-inference","ollama","ray","torchserve","tensorflow-serving","kserve","seldon","bentoml","litellm","sglang"],
  ["AML.T0040","T1190"]),
 ("serving_stack","ml_runtime",["PythonPackage","SoftwareLibrary","SharedLibraryFile","Software"],
  ["torch","pytorch","tensorflow","transformers","onnx","onnxruntime","cuda","cudnn","nvidia","tensorrt","jax"],
  ["AML.T0010","T1195"]),
 ("web_frontend","api_gateway",["WebServerApplication","WebServer","ReverseProxyServer","Software"],
  ["nginx","envoy","haproxy","apache2","httpd","traefik","gunicorn","uvicorn","caddy"],
  ["T1190","T1133"]),
 ("host_privesc","privilege_mgmt",["AccessToken","UserAccount","OperatingSystem"],
  ["sudo","policykit","polkit","pkexec","systemd","dbus"],
  ["T1548","T1543","T1053"]),
 ("crypto_network","crypto_transport",["Certificate","CertificateFile","CryptographicKey","TrustStore"],
  ["openssl","libssl","libcrypto","openssl-libs","gnutls","openssh","libssh","curl","libcurl","glibc","libc6","nss","libnss"],
  ["T1552","T1573","T1557","T1040"]),
 ("auth_secrets","auth_credentials",["CredentialManagementSystem","Credential","AuthenticationService","PasswordDatabase"],
  ["pam","libpam","sssd","keyring","gnupg","gpg","vault","sasl","libsasl","krb5","kerberos"],
  ["T1552","T1078","T1556"]),
]

PROFILES = {
 "strict":   ["serving_stack","isolation_boundary","host_privesc"],
 "standard": ["serving_stack","isolation_boundary","host_privesc","crypto_network","auth_secrets","web_frontend"],
 "full":     ["serving_stack","isolation_boundary","host_privesc","crypto_network","auth_secrets","web_frontend"],
}

# Non-runtime package families -> never in scope: source modules, dev headers,
# docs, debug symbols. A CVE on a Go-source or -dev package is not the installed
# runtime's exposure. Agnostic + cross-distro (Debian golang-/rust-/node- source
# conventions; -dev/-devel headers; -doc/-dbg artifacts).
EXCLUDE = [
 r"^golang-", r"^rust-", r"^node-",
 r"-(dev|devel|doc|docs|dbg|dbgsym|source|src)$",
]

def load_nodes():
    if not NODES.is_file(): return None
    n = json.load(open(NODES, encoding="utf-8"))
    return n if isinstance(n, dict) else {x.get("id"): x for x in n if isinstance(x, dict)}

def load_artifacts():
    if not MAP.is_file(): return None, {}
    m = json.load(open(MAP, encoding="utf-8"))
    a2d = m.get("artifact_to_defenses", {})
    return set(m.get("artifact_labels", {})) | set(a2d), a2d

def main():
    nodes = load_nodes(); arts, a2d = load_artifacts()
    if nodes is None: print("no graph at", NODES, "- run ./run.sh once first"); return 1
    if not arts: print("no artifact map at", MAP, "- run data/d3fend_extract.py first"); return 1

    groups = []
    print("=== relevance role-group build · grounding report ===")
    print("%-16s %-18s pat tech      artifact                     def" % ("group","tier"))
    for tier, name, cands, patterns, techs in SEED:
        iri = next((DAO+c for c in cands if DAO+c in arts), "")
        kept = [t for t in techs if (nodes.get(t) or {}).get("type") == "technique"]
        dropped = [t for t in techs if t not in kept]
        defenses = len(a2d.get(iri, []))
        groups.append({"name":name,"tier":tier,"patterns":patterns,"techniques":kept,"d3fend_artifact":iri})
        art = iri.split("#")[-1] if iri else "*** NONE ***"
        print("%-16s %-18s %3d %d/%-2d    %-28s %3d%s" % (name, tier, len(patterns),
              len(kept), len(techs), art, defenses,
              ("  DROP:"+",".join(dropped)) if dropped else ""))

    L = ["# Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.",
         "# packs/relevance/role-groups.yaml — GENERATED by data/relevance_build.py.",
         "# Relevance = scope, not severity. Agnostic: patterns match upstream project",
         "# names (cross-distro). Grounded: techniques are graph nodes; d3fend_artifact",
         "# is a real D3FEND artifact IRI. Out-of-profile groups route CVEs to catalog.",
         "profiles:"]
    for p, ts in PROFILES.items(): L.append("  %s: [%s]" % (p, ", ".join(ts)))
    L.append("exclude:  # non-runtime/source/dev families -> never in scope (agnostic, cross-distro)")
    for rx in EXCLUDE: L.append('  - "%s"' % rx)
    L.append("role_groups:")
    for g in groups:
        L += ["  - name: %s" % g["name"],
              "    tier: %s" % g["tier"],
              "    patterns: [%s]" % ", ".join(g["patterns"]),
              "    techniques: [%s]" % ", ".join(g["techniques"]),
              "    d3fend_artifact: \"%s\"" % g["d3fend_artifact"]]
    OUT.write_text("\n".join(L) + "\n", encoding="utf-8")

    tiers = sorted({g["tier"] for g in groups})
    needfix = [g["name"] for g in groups if not g["techniques"] or not g["d3fend_artifact"]]
    print("--- summary ---")
    print("groups: %d | tiers: %d %s" % (len(groups), len(tiers), tiers))
    print("profiles:", {k: len(v) for k, v in PROFILES.items()})
    print("NEEDS FIX (no grounded technique or no artifact):", needfix or "none")
    print("wrote", OUT)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
