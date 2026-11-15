#!/usr/bin/env python3
"""Bounded offline XZ/tar metadata scan. Never materialize archive member files."""
import argparse
import configparser
import hashlib
import json
import lzma
import os
from pathlib import Path
import resource
import signal
import stat
import subprocess
import sys
import time
import tomllib

HERE = Path(__file__).resolve().parent
MIB = 1024**2
CHUNK = 64 * 1024
LIMITS = {"headers": 500_000, "logical": 8 * 1024**3, "metadata": 32 * MIB,
          "retained": 16 * MIB, "address_space": 512 * MIB, "seconds": 300,
          "worker_address_space": 448 * MIB, "supervisor_address_space": 64 * MIB,
          "xz_decoder_memory": 320 * MIB, "prefix_records": 100_000,
          "vendor_records": 10_000, "path_bytes": 16_384, "pax_records": 512}
RUST_SELECT = {"LICENSE-MIT", "LICENSE-APACHE", "COPYRIGHT", "Cargo.lock", "Cargo.toml",
               ".gitmodules", ".cargo/config", ".cargo/config.toml", "src/stage0",
               "src/tools/cargo/Cargo.lock", "src/tools/cargo/Cargo.toml",
               "src/tools/cargo/.gitmodules", "src/tools/cargo/LICENSE-MIT",
               "src/tools/cargo/LICENSE-APACHE", "src/llvm-project/LICENSE.TXT"}
LLVM_SELECT = {"LICENSE.TXT", ".gitmodules", "llvm/LICENSE.TXT", "compiler-rt/LICENSE.TXT",
               "lld/LICENSE.TXT", "clang/LICENSE.TXT", "libcxx/LICENSE.TXT",
               "libcxxabi/LICENSE.TXT", "third-party/benchmark/LICENSE"}


class BoundError(ValueError):
    pass


def regular_input(path, size=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    source = os.fdopen(fd, "rb")
    info = os.fstat(source.fileno())
    if not stat.S_ISREG(info.st_mode) or (size is not None and info.st_size != size):
        source.close()
        raise BoundError("input must be a regular, exact-size file")
    return source


def file_pin(path, expected=None):
    with regular_input(path, expected["bytes"] if expected else None) as source:
        if os.fstat(source.fileno()).st_size > LIMITS["retained"]:
            raise BoundError("evidence/report file exceeds metadata bound")
        digest = hashlib.file_digest(source, "sha256").hexdigest()
        return {"bytes": source.tell(), "sha256": digest}


def validate_inputs():
    inputs = json.loads((HERE / "inputs.json").read_text())
    for relative, expected in inputs["prior_evidence"].items():
        if file_pin(HERE.parent / relative, expected) != expected:
            raise BoundError("prior source authentication evidence changed")
    parent = json.loads((HERE.parent / "source-inputs.json").read_text())
    authenticated = json.loads((HERE.parent / inputs["authentication_report"]).read_text())
    if set(inputs["archives"]) != {"rust", "llvm"}:
        raise BoundError("this successor is limited to the two authenticated archives")
    for name, spec in inputs["archives"].items():
        original = parent["archives"][spec["filename"]]
        verified = authenticated["source_signatures"][name]
        if (spec["bytes"] != original["bytes"] or spec["sha256"] != original["checksums"]["sha256"]
                or verified["signature_mathematics"] != "PASS"
                or verified["archive"] != {"archive": spec["filename"], "bytes": spec["bytes"], "sha256": spec["sha256"]}):
            raise BoundError("archive descriptor differs from authenticated original")
    return inputs


class XZReader:
    """One XZ stream; bounded decoder memory and bounded output on every call."""
    def __init__(self, source, spec, limits=LIMITS):
        self.source, self.spec, self.limits = source, spec, limits
        self.decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ,
                                          memlimit=limits["xz_decoder_memory"])
        self.digest = hashlib.sha256()
        self.compressed = self.logical = 0
        self.finished = False

    def compressed_read(self):
        block = self.source.read(CHUNK)
        self.compressed += len(block)
        if self.compressed > self.spec["bytes"]:
            raise BoundError("compressed byte bound exceeded")
        self.digest.update(block)
        return block

    def finish(self):
        # Accept only XZ's optional zero stream-padding, never another stream.
        trailing = self.decoder.unused_data
        padding = len(trailing)
        if trailing.strip(b"\0"):
            raise BoundError("concatenated XZ streams or trailing compressed data")
        while block := self.compressed_read():
            padding += len(block)
            if block.strip(b"\0"):
                raise BoundError("trailing compressed data")
        if padding % 4 or self.compressed != self.spec["bytes"] or self.digest.hexdigest() != self.spec["sha256"]:
            raise BoundError("compressed source pin or XZ padding mismatch")
        self.finished = True

    def read(self, amount):
        if amount > CHUNK or amount < 0:
            raise BoundError("reader requests must be bounded")
        if self.finished:
            return b""
        while True:
            if self.decoder.eof:
                self.finish()
                return b""
            remaining = self.limits["logical"] - self.logical
            if remaining <= 0:
                raise BoundError("logical decompression bound reached")
            data = self.compressed_read() if self.decoder.needs_input else b""
            if self.decoder.needs_input and not data:
                raise BoundError("truncated XZ stream")
            block = self.decoder.decompress(data, max_length=min(amount, remaining))
            self.logical += len(block)
            if block:
                return block


def exact(reader, size):
    chunks = []
    while size:
        block = reader.read(min(size, CHUNK))
        if not block:
            raise BoundError("truncated tar member/header")
        chunks.append(block)
        size -= len(block)
    return b"".join(chunks)


def discard(reader, size):
    while size:
        block = reader.read(min(size, CHUNK))
        if not block:
            raise BoundError("truncated tar payload")
        size -= len(block)


def number(field):
    if field[0] & 128:
        if field[0] & 64:
            raise BoundError("negative tar numeric field")
        return int.from_bytes(bytes([field[0] & 127]) + field[1:], "big")
    clean = field.rstrip(b"\0 ").lstrip(b" ")
    if not clean:
        return 0
    if any(c not in b"01234567" for c in clean):
        raise BoundError("invalid octal tar number")
    return int(clean, 8)


def pax_fields(data, limits=LIMITS):
    fields, offset, count = {}, 0, 0
    while offset < len(data):
        space = data.find(b" ", offset, offset + 12)
        if space < 0 or not data[offset:space].isdigit():
            raise BoundError("invalid PAX record length")
        length = int(data[offset:space])
        end = offset + length
        if length <= space - offset + 2 or end > len(data) or data[end - 1] != 10:
            raise BoundError("invalid PAX record boundary")
        key, separator, value = data[space + 1:end - 1].partition(b"=")
        count += 1
        if not separator or count > limits["pax_records"] or b"sparse" in key.lower():
            raise BoundError("unsupported/bounded PAX record")
        if key in (b"path", b"linkpath", b"size"):
            if len(value) > limits["path_bytes"]:
                raise BoundError("PAX field exceeds path bound")
            fields[key.decode()] = value.decode("utf-8", errors="strict")
            if key == b"size" and (len(value) > 20 or not value.isdigit()):
                raise BoundError("invalid bounded PAX size")
        offset = end
    return fields


def clean_path(name, root, limits=LIMITS):
    if len(name.encode("utf-8")) > limits["path_bytes"]:
        raise BoundError("member path exceeds bound")
    while name.startswith("./"):
        name = name[2:]
    parts = name.rstrip("/").split("/")
    if (len(parts) > 64 or any(p in ("", ".", "..") for p in parts)
            or parts[0] != root or "\0" in name):
        raise BoundError("unsafe or unexpected archive root/path")
    return "/".join(parts[1:])


def declarations(path, body):
    """Parse declarations as data; never load a package, config module or script."""
    if path.endswith("Cargo.lock"):
        lock = tomllib.loads(body.decode("utf-8"))
        return {"packages": [{key: item[key] for key in ("name", "version", "source", "checksum")
                              if key in item} for item in lock.get("package", [])]}
    if path.endswith("Cargo.toml"):
        manifest = tomllib.loads(body.decode("utf-8"))
        package = manifest.get("package", {})
        return {"package": {key: package[key] for key in ("name", "version", "license", "license-file")
                            if key in package}, "workspace_members": manifest.get("workspace", {}).get("members", [])}
    if path.endswith((".cargo/config", ".cargo/config.toml")):
        config = tomllib.loads(body.decode("utf-8"))
        return {key: config[key] for key in ("source", "net") if key in config}
    if path.endswith(".gitmodules"):
        config = configparser.ConfigParser(interpolation=None, strict=True)
        config.read_string(body.decode("utf-8"))
        return {"submodules": [{key: config[section][key] for key in ("path", "url", "branch")
                                if key in config[section]} for section in config.sections()]}
    if path.endswith(".cargo-checksum.json"):
        checksums = json.loads(body)
        return {"package_checksum": checksums.get("package"),
                "declared_file_checksums": len(checksums.get("files", {}))}
    if path == "src/stage0":
        # Plain release/checksum declarations only. Do not invoke bootstrap.
        text = body.decode("utf-8")
        return {"lines": len(text.splitlines()), "contains_download_urls": "https://" in text,
                "bootstrap_components": sorted({word for word in ("rustc", "cargo", "rust-std") if word in text})}
    return None


class Inventory:
    def __init__(self, reader, spec, limits=LIMITS):
        self.reader, self.spec, self.limits = reader, spec, limits
        self.headers = self.payload = 0
        self.types, self.prefixes, self.vendors = {}, {}, {}
        self.selected, self.parse_errors = [], []

    def metadata(self, path, size, parse):
        if size > self.limits["metadata"]:
            raise BoundError("individual selected metadata bound exceeded")
        digest, pieces = hashlib.sha256(), []
        remaining = size
        while remaining:
            block = exact(self.reader, min(remaining, CHUNK))
            digest.update(block)
            if parse:
                pieces.append(block)
            remaining -= len(block)
        record = {"path": path, "bytes": size, "sha256": digest.hexdigest()}
        if parse:
            try:
                record["declarations"] = declarations(path, b"".join(pieces))
            except (ValueError, KeyError, TypeError, configparser.Error) as error:
                self.parse_errors.append({"path": path, "error": str(error)[:500]})
        return record

    def entry(self, path, size, kind):
        self.types[kind] = self.types.get(kind, 0) + 1
        self.payload += size
        parts = path.split("/") if path else []
        # Directory prefixes suffice for submodule topology; retaining every
        # regular-file path would consume a record for each source file.
        directory_depth = len(parts) if kind == "5" else max(0, len(parts) - 1)
        for depth in range(1, min(directory_depth, 8) + 1):
            prefix = "/".join(parts[:depth])
            if prefix not in self.prefixes and len(self.prefixes) >= self.limits["prefix_records"]:
                raise BoundError("prefix record bound reached")
            self.prefixes[prefix] = self.prefixes.get(prefix, 0) + (kind in ("0", "\0"))
        vendor = None
        if len(parts) >= 2 and parts[0] == "vendor":
            if parts[1] not in self.vendors and len(self.vendors) >= self.limits["vendor_records"]:
                raise BoundError("vendor component bound reached")
            vendor = self.vendors.setdefault(parts[1], {"regular_files": 0, "bytes": 0, "licenses": []})
            if kind in ("0", "\0"):
                vendor["regular_files"] += 1
                vendor["bytes"] += size
        selectors = RUST_SELECT if self.spec["name"] == "rust" else LLVM_SELECT
        leaf = parts[-1].upper() if parts else ""
        license_file = bool(vendor and leaf.startswith(("LICENSE", "COPYING", "NOTICE", "UNLICENSE", "COPYRIGHT")))
        vendor_declaration = bool(vendor and len(parts) == 3 and parts[2] in ("Cargo.toml", ".cargo-checksum.json"))
        selected = path in selectors or license_file or vendor_declaration
        if selected and kind not in ("0", "\0"):
            self.selected.append({"path": path, "bytes": size, "type": kind, "metadata": "NOT_REGULAR_NOT_FOLLOWED"})
            discard(self.reader, size)
        elif selected:
            parse = path.endswith(("Cargo.lock", "Cargo.toml", ".gitmodules", ".cargo-checksum.json", ".cargo/config", ".cargo/config.toml")) or path == "src/stage0"
            record = self.metadata(path, size, parse)
            if license_file:
                vendor["licenses"].append(record)
            elif vendor_declaration:
                vendor[parts[2]] = record
            else:
                self.selected.append(record)
        else:
            discard(self.reader, size)

    def scan(self):
        global_pax, local_pax, long_name = {}, {}, None
        while True:
            if self.headers >= self.limits["headers"]:
                raise BoundError("physical header bound reached")
            header = exact(self.reader, 512)
            if header == bytes(512):
                if exact(self.reader, 512) != bytes(512):
                    raise BoundError("tar requires two zero end markers")
                while block := self.reader.read(CHUNK):
                    if block.strip(b"\0"):
                        raise BoundError("nonzero data after tar end markers")
                return
            self.headers += 1
            if sum(header[:148]) + 8 * 32 + sum(header[156:]) != number(header[148:156]):
                raise BoundError("tar header checksum mismatch")
            size = number(header[124:136])
            if size > self.limits["logical"]:
                raise BoundError("declared tar size exceeds logical bound")
            kind = chr(header[156])
            name = header[:100].split(b"\0", 1)[0]
            if header[257:263] == b"ustar\0":
                prefix = header[345:500].split(b"\0", 1)[0]
                name = prefix + b"/" + name if prefix else name
            if kind in ("x", "g", "L", "K"):
                if size > self.limits["metadata"]:
                    raise BoundError("extended tar metadata bound exceeded")
                data = exact(self.reader, size)
                if kind in ("x", "g"):
                    fields = pax_fields(data, self.limits)
                    if kind == "g":
                        global_pax.update(fields)
                    else:
                        local_pax = fields
                elif kind == "L":
                    if size > self.limits["path_bytes"]:
                        raise BoundError("GNU long path exceeds bound")
                    long_name = data.rstrip(b"\0").decode("utf-8", errors="strict")
                # K long links are never followed or retained.
                discard(self.reader, (-size) % 512)
                continue
            if kind not in ("0", "\0", "1", "2", "3", "4", "5", "6", "7"):
                raise BoundError("unsupported tar entry type (including sparse)")
            fields = {**global_pax, **local_pax}
            if "size" in fields:
                if not fields["size"].isdigit():
                    raise BoundError("invalid PAX size")
                size = int(fields["size"])
                if size > self.limits["logical"]:
                    raise BoundError("PAX size exceeds logical bound")
            path = clean_path(fields.get("path", long_name or name.decode("utf-8", errors="strict")), self.spec["root"], self.limits)
            self.entry(path, size, kind)
            discard(self.reader, (-size) % 512)
            local_pax, long_name = {}, None

    def report(self, error):
        modules = []
        for record in self.selected:
            for module in (record.get("declarations") or {}).get("submodules", []):
                parent = record["path"].rsplit("/", 1)[0] if "/" in record["path"] else ""
                path = (parent + "/" if parent else "") + module.get("path", "")
                modules.append({**module, "archive_relative_path": path,
                                "regular_members_under_path": self.prefixes.get(path, 0),
                                "presence_is_not_revision_or_completeness_proof": True})
        return {"archive": self.spec, "status": "PARTIAL" if error else "COMPLETE_BOUNDED_SCAN",
                "stop_reason": error, "physical_headers": self.headers,
                "declared_member_payload_bytes": self.payload,
                "logical_bytes_read": self.reader.logical,
                "compressed_bytes_read": self.reader.compressed,
                "compressed_sha256_observed": self.reader.digest.hexdigest(),
                "authenticated_source_pin_verified": self.reader.finished and not error,
                "entry_types": self.types, "selected_metadata": self.selected,
                "vendor_components": self.vendors, "submodule_declarations": modules,
                "metadata_parse_errors": self.parse_errors, "archive_member_payload_bytes_written": 0,
                "limits": self.limits, "scope": "metadata hashes/declarations only; links never followed",
                "offline_build_or_license_acceptance": "NOT_ESTABLISHED"}


def alarm(_signum, _frame):
    raise BoundError("per-archive wall deadline")


def worker(cache, name, output, remaining):
    resource.setrlimit(resource.RLIMIT_AS, (LIMITS["worker_address_space"], LIMITS["worker_address_space"]))
    resource.setrlimit(resource.RLIMIT_FSIZE, (remaining, remaining))
    signal.signal(signal.SIGALRM, alarm)
    signal.setitimer(signal.ITIMER_REAL, LIMITS["seconds"] - 2)
    inputs = validate_inputs()
    spec = inputs["archives"][name]
    started = time.monotonic()
    with regular_input(cache / spec["filename"], spec["bytes"]) as source:
        reader = XZReader(source, spec)
        inventory = Inventory(reader, spec)
        error = None
        try:
            inventory.scan()
        except (BoundError, lzma.LZMAError, UnicodeError, MemoryError, RecursionError) as failure:
            error = type(failure).__name__ + ": " + str(failure)[:500]
        signal.setitimer(signal.ITIMER_REAL, 0)
        result = inventory.report(error)
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        result["peak_RSS_bytes"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
        encoded = (json.dumps(result, sort_keys=True, indent=2) + "\n").encode()
        if len(encoded) > remaining:
            result["status"] = "PARTIAL"
            result["stop_reason"] = "retained metadata quota; detailed records omitted"
            result["selected_metadata"], result["vendor_components"], result["submodule_declarations"] = [], {}, []
            encoded = (json.dumps(result, sort_keys=True, indent=2) + "\n").encode()
        if len(encoded) > remaining:
            raise BoundError("remaining metadata quota cannot hold partial report")
        with output.open("xb") as target:
            target.write(encoded)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--worker", choices=("rust", "llvm"))
    parser.add_argument("--remaining", type=int, default=LIMITS["retained"])
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(Path("/tmp")):
        parser.error("private output must be below /tmp")
    if not 64 * 1024 <= args.remaining <= LIMITS["retained"]:
        parser.error("metadata quota outside fixed bounds")
    if args.worker:
        worker(args.cache.resolve(), args.worker, output, args.remaining)
        return
    # Children inherit the hard ceiling; only the parent's effective soft bound
    # is 64MiB, so a child can set its own 448MiB soft ceiling before decoding.
    resource.setrlimit(resource.RLIMIT_AS, (LIMITS["supervisor_address_space"], LIMITS["worker_address_space"]))
    inputs = validate_inputs()
    for spec in inputs["archives"].values():
        with regular_input(args.cache / spec["filename"], spec["bytes"]):
            pass
    output.mkdir(mode=0o700, exist_ok=False)
    results = {}
    for name in ("rust", "llvm"):
        retained = sum(p.stat().st_size for p in output.iterdir() if p.is_file())
        remaining = LIMITS["retained"] - retained - 256 * 1024
        if remaining < 64 * 1024:
            results[name] = {"status": "NOT_RUN", "stop_reason": "global retained metadata quota"}
            continue
        target = output / (name + ".json")
        command = [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--cache",
                   str(args.cache.resolve()), "--output", str(target), "--worker", name,
                   "--remaining", str(remaining)]
        try:
            completed = subprocess.run(command, timeout=LIMITS["seconds"], capture_output=True,
                                       env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"})
            result = json.loads(target.read_text()) if target.exists() else {
                "status": "PARTIAL", "stop_reason": "worker failed before report", "exit": completed.returncode,
                "stderr": completed.stderr.decode(errors="replace")[:2000]}
        except subprocess.TimeoutExpired:
            result = {"status": "PARTIAL", "stop_reason": "supervisor killed worker at 300s"}
        results[name] = {key: result.get(key) for key in ("status", "stop_reason", "authenticated_source_pin_verified")}
        if target.exists():
            results[name]["report"] = file_pin(target)
    summary = {"results": results, "limits": LIMITS, "network_requests": 0,
               "payload_extraction_evaluation_import_execution": "NOT_RUN",
               "native_Source_Reader_jobs": "NOT_RUN", "prior_evidence_unchanged": True}
    data = (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode()
    if sum(p.stat().st_size for p in output.iterdir() if p.is_file()) + len(data) > LIMITS["retained"]:
        raise BoundError("global retained metadata quota exceeded")
    (output / "summary.json").write_bytes(data)
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
