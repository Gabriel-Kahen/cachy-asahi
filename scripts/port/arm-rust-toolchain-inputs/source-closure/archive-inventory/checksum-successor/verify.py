#!/usr/bin/env python3
"""Stream vendor bytes into hashes; keep only bounded review prefixes privately."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import signal
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
PARENT = HERE.parent
MIB = 1024**2
RETAIN = 6 * MIB                 # Stricter than the delegated 16MiB ceiling.
TEXT_BUDGET = 2 * MIB
RESERVE = 8 * 1024**3


def pinned(path, expected):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size != expected["bytes"]:
            raise ValueError("pinned file type/size changed")
        if hashlib.file_digest(source, "sha256").hexdigest() != expected["sha256"]:
            raise ValueError("pinned input SHA256 changed")


INPUTS = json.loads((HERE / "inputs.json").read_text())
pinned(PARENT / "inventory.py", INPUTS["parser"])
SPEC = importlib.util.spec_from_file_location("bounded_inventory", PARENT / "inventory.py")
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)       # Our pinned parser, never archive code.


def memory_available():
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    raise BASE.BoundError("MemAvailable unavailable")


class ReserveReader(BASE.XZReader):
    def __init__(self, *args):
        super().__init__(*args)
        self.next_check = 0
        self.lowest_available = memory_available()

    def read(self, amount):
        if time.monotonic() >= self.next_check:
            available = memory_available()
            self.lowest_available = min(self.lowest_available, available)
            self.next_check = time.monotonic() + 0.5
            if available < RESERVE:
                raise BASE.BoundError("global8GiB RAM reserve reached")
        return super().read(amount)


def relative_path(value):
    if (not isinstance(value, str) or len(value.encode()) > 16384
            or "\\" in value or "\0" in value
            or any(part in ("", ".", "..") for part in value.split("/"))):
        raise BASE.BoundError("noncanonical checksum/member path")
    return value


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BASE.BoundError("duplicate JSON key")
        result[key] = value
    return result


def checksum_map(body):
    data = json.loads(body, object_pairs_hook=unique_pairs)
    if not isinstance(data, dict) or "files" not in data or set(data) - {"files", "package", "$comment"} or not isinstance(data["files"], dict):
        fields = sorted(data) if isinstance(data, dict) else type(data).__name__
        raise BASE.BoundError("invalid checksum map schema: " + str(fields)[:300])
    if len(data["files"]) > 200_000:
        raise BASE.BoundError("checksum path count bound")
    # Signed source maps contain this JSON annotation. It never supplies paths,
    # digests or permissions; the full marker bytes remain independently pinned.
    if "$comment" in data and (not isinstance(data["$comment"], str) or len(data["$comment"].encode()) > 4096):
        raise BASE.BoundError("unsupported checksum comment metadata")
    package = data.get("package")
    if package is not None and (not isinstance(package, str) or len(package) != 64 or any(c not in "0123456789abcdef" for c in package)):
        raise BASE.BoundError("invalid package checksum declaration")
    files = {}
    for path, digest in data["files"].items():
        relative_path(path)
        if path == ".cargo-checksum.json":
            raise BASE.BoundError("checksum map cannot self-authorize")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise BASE.BoundError("invalid file SHA256 declaration")
        files[path] = bytes.fromhex(digest)
    return files, package


def comparison(members, expected, aliases):
    actual = {p: row[1] for p, row in members.items() if row[0] in ("0", "\0") and p != ".cargo-checksum.json"}
    missing = sorted(set(expected) - set(actual))
    changed = sorted(p for p in set(expected) & set(actual) if expected[p] != actual[p])
    extra = sorted(set(actual) - set(expected))
    refused = sorted(p for p, row in members.items() if row[0] not in ("0", "\0", "5"))
    counts = {"missing": len(missing), "changed": len(changed), "extra": len(extra),
              "refused_nonregular": len(refused), "aliases": len(aliases)}
    return {"status": "FAIL_OR_REFUSED" if any(counts.values()) else "PASS",
            "expected_files": len(expected), "actual_regular_files_excluding_marker": len(actual),
            "matched_files": len(expected) - len(missing) - len(changed), "issues": counts,
            "samples": {"missing": missing[:8], "changed": changed[:8], "extra": extra[:8],
                        "refused_nonregular": refused[:8], "aliases": aliases[:8]}}


def candidate_limit(path):
    leaf = path.rsplit("/", 1)[-1].upper()
    if leaf.startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE", "UNLICENSE", "COPYRIGHT")):
        return 32 * 1024
    if "/" not in path and leaf.startswith(("README", "AUTHORS")):
        return 16 * 1024
    if path in ("src/lib.rs", "src/main.rs", "lib.rs", "Cargo.toml.orig", ".cargo_vcs_info.json"):
        return 8 * 1024
    return 0


class Checksums(BASE.Inventory):
    def __init__(self, reader, spec, previous, targets):
        super().__init__(reader, spec)
        self.previous, self.targets = previous, set(targets)
        self.members, self.expected, self.markers, self.aliases, self.parents = {}, {}, {}, {}, {}
        self.candidates, self.captured = [], 0
        self.capture_omissions = []
        self.component_roots, self.member_count = set(), 0
        self.vendor_root_seen, self.map_errors = False, {}
        self.current_path = None

    def entry(self, path, size, kind):
        self.current_path = path
        self.types[kind] = self.types.get(kind, 0) + 1
        self.payload += size
        parts = path.split("/")
        if path == "vendor":
            if kind != "5" or size != 0 or self.vendor_root_seen:
                raise BASE.BoundError("vendor root is non-directory/nonempty/duplicate")
            self.vendor_root_seen = True
            return
        if len(parts) < 2 or parts[0] != "vendor":
            BASE.discard(self.reader, size)
            return
        crate = parts[1]
        if len(parts) == 2:
            if kind != "5" or size != 0:
                raise BASE.BoundError("vendor component root is not an empty directory entry")
            if crate in self.component_roots:
                self.aliases.setdefault(crate, []).append("<duplicate-component-root>")
            self.component_roots.add(crate)
            return
        relative = relative_path("/".join(parts[2:]))
        members = self.members.setdefault(crate, {})
        parents = self.parents.setdefault(crate, set())
        aliases = self.aliases.setdefault(crate, [])
        ancestors = ["/".join(parts[2:n]) for n in range(3, len(parts))]
        collision = relative in members or (kind != "5" and relative in parents)
        collision |= any(p in members and members[p][0] != "5" for p in ancestors)
        if collision:
            if len(aliases) >= 16:
                raise BASE.BoundError("alias diagnostic bound")
            aliases.append(relative)
        parents.update(ancestors)
        marker = relative == ".cargo-checksum.json"
        if marker and size > BASE.LIMITS["metadata"]:
            raise BASE.BoundError("individual checksum metadata cap")
        capture = candidate_limit(relative) if crate in self.targets else 0
        if self.captured + min(size, capture) > TEXT_BUDGET:
            self.capture_omissions.append(path)
            capture = 0
        digest, body, prefix = hashlib.sha256(), [], bytearray()
        remaining = size
        while remaining:
            block = BASE.exact(self.reader, min(BASE.CHUNK, remaining))
            digest.update(block)
            if marker:
                body.append(block)
            if capture and len(prefix) < capture:
                prefix.extend(block[:capture - len(prefix)])
            remaining -= len(block)
        if not collision:
            members[relative] = (kind, digest.digest(), size)
            self.member_count += 1
        if marker:
            if kind not in ("0", "\0") or crate in self.markers:
                raise BASE.BoundError("duplicate or nonregular authoritative checksum marker")
            self.markers[crate] = {"bytes": size, "sha256": digest.hexdigest()}
            try:
                self.expected[crate], package = checksum_map(b"".join(body))
                self.markers[crate]["package_checksum"] = package
            except (BASE.BoundError, ValueError, TypeError) as failure:
                self.map_errors[crate] = str(failure)[:500]
        if capture and kind in ("0", "\0"):
            text = bytes(prefix).decode("utf-8", errors="replace")
            self.candidates.append({"crate": crate, "path": path, "bytes": size,
                "sha256": digest.hexdigest(), "captured_bytes": len(prefix),
                "captured_prefix_sha256": hashlib.sha256(prefix).hexdigest(),
                "complete_text": len(prefix) == size, "utf8_replacement_used": "\ufffd" in text,
                "text": text})
            self.captured += len(prefix)
        if self.member_count > 200_000:
            raise BASE.BoundError("vendor member record cap")

    def results(self):
        results = {}
        for crate in sorted(set(self.previous) | set(self.members) | set(self.expected)):
            if crate not in self.expected:
                results[crate] = {"status": "UNRESOLVED_INVALID_CHECKSUM_MAP" if crate in self.map_errors else "UNRESOLVED_MISSING_CHECKSUM_MAP",
                                  "error": self.map_errors.get(crate), "checksum_marker": self.markers.get(crate)}
                continue
            result = comparison(self.members.get(crate, {}), self.expected[crate], self.aliases.get(crate, []))
            marker = self.markers[crate]
            old_marker = self.previous.get(crate, {}).get(".cargo-checksum.json", {})
            result["marker_matches_prior_authenticated_inventory"] = all(marker.get(k) == old_marker.get(k) for k in ("bytes", "sha256"))
            if not result["marker_matches_prior_authenticated_inventory"]:
                result["status"] = "FAIL_MARKER_IDENTITY"
            result["checksum_marker"] = marker
            result["comparison_digest_sha256"] = hashlib.sha256(b"".join(
                p.encode() + b"\0" + digest for p, digest in sorted(self.expected[crate].items()))).hexdigest()
            results[crate] = result
        return results


def write_json(path, data, remaining):
    body = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode()
    if len(body) > remaining:
        raise BASE.BoundError("retained successor metadata cap")
    with path.open("xb") as target:
        target.write(body)
    return len(body)


def worker(cache, output):
    resource.setrlimit(resource.RLIMIT_AS, (448 * MIB, 448 * MIB))
    resource.setrlimit(resource.RLIMIT_FSIZE, (RETAIN, RETAIN))
    signal.signal(signal.SIGALRM, BASE.alarm)
    signal.setitimer(signal.ITIMER_REAL, 298)
    for name, key in [("inputs.json", "prior_inputs"), ("reports/rust.json", "rust_report"), ("reports/offline-gaps.json", "gap_report")]:
        pinned(PARENT / name, INPUTS[key])
    inputs = BASE.validate_inputs()
    spec = inputs["archives"]["rust"]
    previous = json.loads((PARENT / "reports/rust.json").read_text())["vendor_components"]
    gaps = json.loads((PARENT / "reports/offline-gaps.json").read_text())["vendor_components_without_license_named_files"]
    started = time.monotonic()
    with BASE.regular_input(cache / spec["filename"], spec["bytes"]) as source:
        reader = ReserveReader(source, spec)
        scan = Checksums(reader, spec, previous, [r["directory"] for r in gaps])
        error = None
        try:
            scan.scan()
        except (BASE.BoundError, BASE.lzma.LZMAError, UnicodeError, MemoryError, RecursionError) as failure:
            error = type(failure).__name__ + ": " + str(failure)[:500]
        results = scan.results()
        verified = reader.finished and not error
        report = {"status": "COMPLETE_STREAM" if verified else "PARTIAL", "stop_reason": error,
                  "authenticated_source_pin_verified": verified, "archive": spec,
                  "physical_headers": scan.headers, "logical_bytes_read": reader.logical,
                  "entry_path_at_stop": scan.current_path if error else None,
                  "compressed_bytes_read": reader.compressed,
                  "checksum_components": results, "components_pass": sum(r["status"] == "PASS" for r in results.values()),
                  "components_total": len(results), "regular_vendor_members": sum(
                      row[0] in ("0", "\0") for m in scan.members.values() for row in m.values()),
                  "matched_files": sum(r.get("matched_files", 0) for r in results.values()),
                  "lowest_MemAvailable_bytes": reader.lowest_available,
                  "elapsed_seconds": round(time.monotonic() - started, 3),
                  "peak_RSS_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
                  "captured_prefix_bytes": scan.captured, "capture_omissions": scan.capture_omissions,
                  "archive_member_files_written": 0, "network_requests": 0,
                  "old_reports_unchanged": True, "original_recipe_hashes_resolved": 0,
                  "component_results_require_complete_authenticated_stream": True,
                  "checksum_comment_semantics": "$comment string accepted as annotation only; marker bytes pinned; files/path/digest checks unchanged",
                  "scope": "file integrity against signed-source declarations; no original crate/binary/legal acceptance"}
        used = write_json(output / "checksums.json", report, RETAIN - 64 * 1024)
        write_json(output / "private-license-candidates.json", {"private_review_only": True,
            "unknown_full_text_not_authorized_for_publication": True, "source_pin_verified": verified,
            "targets": [r["directory"] for r in gaps], "candidates": scan.candidates,
            "component_statuses": {r["directory"]: results.get(r["directory"], {}).get("status") for r in gaps},
            "capture_omissions": scan.capture_omissions}, RETAIN - used - 64 * 1024)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--worker", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(Path("/tmp")):
        parser.error("new private output must be below /tmp")
    if args.worker:
        worker(args.cache, output)
        return
    resource.setrlimit(resource.RLIMIT_AS, (64 * MIB, 448 * MIB))
    available = memory_available()
    if available < RESERVE + 512 * MIB + RETAIN:
        raise BASE.BoundError("reserve8GiB plus512MiB process/output headroom unavailable")
    output.mkdir(mode=0o700, exist_ok=False)
    started = time.monotonic()
    try:
        result = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve()),
            "--cache", str(args.cache.resolve()), "--output", str(output), "--worker"],
            capture_output=True, timeout=300, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"})
        status = ("WORKER_EXIT_" if result.returncode == 0 else "PARTIAL_WORKER_EXIT_") + str(result.returncode)
        diagnostic = result.stderr.decode(errors="replace")[:2000]
    except subprocess.TimeoutExpired:
        status, diagnostic = "PARTIAL_TIMEOUT", "supervisor killed worker at300seconds"
    retained = sum(p.stat().st_size for p in output.iterdir() if p.is_file())
    write_json(output / "run.json", {"status": status, "diagnostic": diagnostic,
        "elapsed_seconds": round(time.monotonic() - started, 3), "initial_MemAvailable_bytes": available,
        "reserve_bytes": RESERVE, "worker_AS_bytes": 448 * MIB, "supervisor_AS_soft_bytes": 64 * MIB,
        "hard_runtime_seconds": 300, "retained_internal_cap": RETAIN,
        "root_limits": BASE.LIMITS}, RETAIN - retained)
    print(json.dumps({"status": status, "output": str(output), "seconds": round(time.monotonic() - started, 3)}))


if __name__ == "__main__":
    main()
