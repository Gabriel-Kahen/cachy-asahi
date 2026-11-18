#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only Apple update policy evaluator. No accepted target policy is shipped.

Both digests must come from a trusted release caller. That caller must authenticate
the release/transition evidence and collect actual package inventories and package-
owned module file lists. A supplied model string or fixture is not hardware proof.
This helper neither collects host state nor authorizes a complete update transaction.
"""

import argparse
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
import sys

# Model identities are documented in docs/baseline.md from Linux Apple DTS files.
MODELS = {"apple,j413", "apple,j415"}
ROLES = {"boot", "kernel", "firmware", "graphics", "audio"}
REQUIRED_AUDIO_PACKAGES = {"asahi-audio", "speakersafetyd"}
REQUIRED_UNITS = {
    "system": {"speakersafetyd.service", "asahi-audio.service"},
    "user": {"pipewire.service", "pipewire-pulse.service", "wireplumber.service"},
}
NAME = re.compile(r"[a-z0-9][a-z0-9+_.-]{0,127}\Z")
RELEASE = re.compile(r"[A-Za-z0-9][A-Za-z0-9+_.-]{0,127}\Z")
UNIT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*(?:@[A-Za-z0-9_.-]+)?\.service\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
OPERATIONS = {"repository-update", "aur-update", "flatpak-update", "orphan-removal",
              "package-cache-removal", "flatpak-unused-removal"}


class Invalid(ValueError):
    pass


def exact(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise Invalid("invalid object fields")


def text(value, pattern=None):
    if type(value) is not str or not 0 < len(value) <= 256 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise Invalid("invalid text")
    if pattern and not pattern.fullmatch(value):
        raise Invalid("invalid identifier")
    return value


def identifiers(value, pattern, limit=128, empty=False):
    if type(value) is not list or not (0 if empty else 1) <= len(value) <= limit:
        raise Invalid("invalid identifier list")
    parsed = [text(item, pattern) for item in value]
    if len(set(parsed)) != len(parsed):
        raise Invalid("duplicate identifier")
    return set(parsed)


def versions(value, names):
    exact(value, names)
    return {name: text(version) for name, version in value.items()}


def module_releases(value, kernels):
    exact(value, kernels)
    return {name: identifiers(items, RELEASE, limit=32) for name, items in value.items()}


def owned_releases(value, kernels):
    """Derive releases from caller-observed package-owned module paths, not versions."""
    exact(value, kernels)
    result = {}
    for package, files in value.items():
        if (type(files) is not list or not 1 <= len(files) <= 32768 or
                any(type(item) is not str for item in files) or len(set(files)) != len(files)):
            raise Invalid("invalid owned module list")
        releases = set()
        for filename in files:
            if type(filename) is not str or len(filename) > 1024:
                raise Invalid("invalid module path")
            parts = PurePosixPath(filename).parts
            if (len(parts) < 7 or parts[:4] != ("/", "usr", "lib", "modules") or
                    not RELEASE.fullmatch(parts[4]) or
                    any(part in {".", ".."} or not RELEASE.fullmatch(part) for part in parts[5:]) or
                    not filename.endswith((".ko", ".ko.xz", ".ko.zst", ".ko.gz")) or
                    str(PurePosixPath(filename)) != filename):
                raise Invalid("invalid module path")
            releases.add(parts[4])
        result[package] = releases
    return result


def critical_unit(unit):
    base = unit[:-8].split("@", 1)[0]
    return base in {"speakersafetyd", "asahi-audio", "pipewire", "pipewire-pulse", "wireplumber"} or base.startswith(("speakersafetyd-", "asahi-audio-"))


def validate(policy, observation):
    exact(policy, {"schema_version", "purpose", "release_id", "compatible_models",
                   "platform_roles", "protected_units", "generic_restart_units", "permitted_operations", "transitions"})
    if type(policy["schema_version"]) is not int or policy["schema_version"] != 1 or policy["purpose"] != "cachy-asahi-apple-update-policy":
        raise Invalid("invalid policy schema")
    text(policy["release_id"], RELEASE)
    models = identifiers(policy["compatible_models"], None, limit=2)
    if not models <= MODELS:
        raise Invalid("unsupported model")
    if not identifiers(policy["permitted_operations"], RELEASE, empty=True) <= OPERATIONS:
        raise Invalid("unsupported transaction operation")
    exact(policy["platform_roles"], ROLES)
    roles = {role: identifiers(names, NAME) for role, names in policy["platform_roles"].items()}
    names = set().union(*roles.values())
    kernels = roles["kernel"]
    if (len(kernels) > 8 or not REQUIRED_AUDIO_PACKAGES <= roles["audio"] or
            kernels & set().union(*(roles[role] for role in ROLES - {"kernel"}))):
        raise Invalid("missing protected platform packages")
    protected, allowed = {}, {}
    for field, result in (("protected_units", protected), ("generic_restart_units", allowed)):
        exact(policy[field], {"system", "user"})
        for scope, units in policy[field].items():
            result[scope] = identifiers(units, UNIT, empty=True)
    if any(not REQUIRED_UNITS[scope] <= protected[scope] for scope in protected):
        raise Invalid("missing protected audio units")
    all_protected = set().union(*protected.values())
    if any(all_protected & units or any(critical_unit(unit) for unit in units) for units in allowed.values()):
        raise Invalid("protected service in generic restart list")
    exact(observation, {"schema_version", "phase", "model", "running_kernel_release", "before_versions",
                        "after_versions", "before_kernel_files", "after_kernel_files"})
    if type(observation["schema_version"]) is not int or observation["schema_version"] != 1:
        raise Invalid("invalid observation schema")
    if observation["phase"] not in {"pre-transaction", "post-transaction"}:
        raise Invalid("invalid observation phase")
    if observation["model"] not in models:
        raise Invalid("model mismatch")
    running = text(observation["running_kernel_release"], RELEASE)
    before = versions(observation["before_versions"], names)
    after = versions(observation["after_versions"], names)
    before_modules = owned_releases(observation["before_kernel_files"], kernels)
    after_modules = owned_releases(observation["after_kernel_files"], kernels)
    transitions = policy["transitions"]
    if type(transitions) is not list or not 1 <= len(transitions) <= 128:
        raise Invalid("invalid transition list")
    matches, ids = [], set()
    for transition in transitions:
        exact(transition, {"id", "model", "before_versions", "after_versions", "before_kernel_releases",
                           "after_kernel_releases", "target_kernel_release", "evidence_sha256"})
        ident = text(transition["id"], RELEASE)
        if ident in ids or transition["model"] not in models:
            raise Invalid("invalid transition identity")
        ids.add(ident)
        tb = versions(transition["before_versions"], names)
        ta = versions(transition["after_versions"], names)
        tmb = module_releases(transition["before_kernel_releases"], kernels)
        tma = module_releases(transition["after_kernel_releases"], kernels)
        target = text(transition["target_kernel_release"], RELEASE)
        if sum(target in releases for releases in tma.values()) != 1:
            raise Invalid("ambiguous or absent target kernel ownership")
        exact(transition["evidence_sha256"], {"release_manifest", "transition_validation"})
        for digest in transition["evidence_sha256"].values():
            text(digest, SHA)
        if (transition["model"] == observation["model"] and tb == before and ta == after and
                tmb == before_modules and tma == after_modules):
            matches.append(transition)
    return names, kernels, protected, allowed, running, before, after, before_modules, after_modules, matches


def evaluate(policy, observation, scope=None, unit=None, action="kernel", operation="repository-update"):
    if action not in {"kernel", "services", "transaction"} or operation not in OPERATIONS:
        raise Invalid("unsupported action or operation")
    names, kernels, protected, allowed, running, before, after, bm, am, matches = validate(policy, observation)
    changes = sorted(name for name in names if before[name] != after[name])
    result = {"decision": "coordination-required", "reason": "unknown-transition", "protected_changes": changes}
    expected_phase = "pre-transaction" if action == "transaction" else "post-transaction"
    if observation["phase"] != expected_phase:
        result["reason"] = "observation-phase-mismatch"
        return result
    if len(matches) != 1:
        return result
    transition = matches[0]
    result["transition_id"] = transition["id"]
    ownership = bm if action == "transaction" else {name: bm[name] | am[name] for name in kernels}
    if sum(running in releases for releases in ownership.values()) != 1:
        result["reason"] = "unknown-or-ambiguous-running-module-owner"
        return result
    if set(changes) - kernels:
        result["reason"] = "protected-platform-changed"
        return result
    target = transition["target_kernel_release"]
    if any(name in kernels for name in changes) and bm == am:
        result["reason"] = "same-release-kernel-package-changed"
        return result
    if action == "transaction":
        if operation not in policy["permitted_operations"]:
            result["reason"] = "operation-not-declared-in-reviewed-policy"
        else:
            result.update(decision="transaction-allowed", reason="caller-pinned-projected-protected-set")
    elif scope is not None:
        if scope not in {"system", "user"}:
            raise Invalid("invalid service scope")
        if unit is None:
            result.update(decision="configured", reason="caller-pinned-transition")
        else:
            text(unit, UNIT)
            if critical_unit(unit) or unit in set().union(*protected.values()):
                result["reason"] = "protected-service-needs-coordination"
            elif unit not in allowed[scope]:
                result["reason"] = "service-not-in-reviewed-allowlist"
            else:
                result.update(decision="restart-allowed", reason="caller-pinned-service-policy")
    elif running != target:
        result.update(decision="reboot-required", reason="caller-pinned-target-module-release")
    else:
        result.update(decision="no-kernel-change", reason="observed-module-release-matches-target")
    return result


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Invalid("duplicate JSON field")
        result[key] = value
    return result


def load_pinned(path, digest, limit):
    text(digest, SHA)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise Invalid("invalid input file")
        data = stream.read(limit + 1)
    if len(data) > limit or hashlib.sha256(data).hexdigest() != digest:
        raise Invalid("input digest mismatch")
    return json.loads(data, object_pairs_hook=unique_object)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["kernel", "services", "transaction"])
    parser.add_argument("--policy")
    parser.add_argument("--policy-sha256")
    parser.add_argument("--observations")
    parser.add_argument("--observations-sha256")
    parser.add_argument("--scope", choices=["system", "user"], default="system")
    parser.add_argument("--unit")
    parser.add_argument("--operation", choices=sorted(OPERATIONS), default="repository-update")
    parser.add_argument("--token", action="store_true")
    args = parser.parse_args(argv)
    if not all((args.policy, args.policy_sha256, args.observations, args.observations_sha256)):
        result = {"decision": "unconfigured", "reason": "trusted-release-inputs-required"}
        code = 21
    else:
        try:
            policy = load_pinned(args.policy, args.policy_sha256, 1048576)
            observation = load_pinned(args.observations, args.observations_sha256, 4194304)
            result = evaluate(policy, observation, args.scope if args.action == "services" else None,
                              args.unit if args.action == "services" else None, args.action, args.operation)
            code = 22 if result["decision"] == "coordination-required" else 0
        except (Invalid, OSError, ValueError, TypeError, RecursionError):
            result = {"decision": "invalid", "reason": "invalid-or-unpinned-release-inputs"}
            code = 23
    print(result["decision"] if args.token else json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
