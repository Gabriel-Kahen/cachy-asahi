#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Import retained release/package/recipe DATA into a held pre-change graph."""
import argparse
from collections import Counter
import importlib.util
import io
import lzma
import os
from pathlib import Path
import stat
import sys
import tarfile
import zlib

ROOT = next(p for p in Path(__file__).resolve().parents
            if (p / "scripts/maintenance/rebuild_plan.py").is_file())


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


b = module("graph_rebuild", "scripts/maintenance/rebuild_plan.py")
a = module("graph_advisory", "scripts/maintenance/security_advisories.py")
c = module("graph_checks", "scripts/checks/package_checks.py")
d = module("graph_build_metadata", "scripts/build/build.py")
v = module("graph_inventory", "scripts/port/maintained_authenticate.py")
need = a.need
MAX_FILES, MAX_TOTAL, MAX_MEMBERS = 512, 96 * 1024**2, 8192


class Reader:
    def __init__(self, root):
        self.root, self.raws, self.pins = root, {}, {}

    def read(self, row):
        b.pins.fields(row, ("path", "sha256"))
        parts = b.s.relative(row["path"])
        path = self.root.joinpath(*parts)
        b.s.sha(row["sha256"])
        if row["path"] not in self.raws:
            need(len(self.raws) < MAX_FILES, "input file count bound")
            raw = a.read(path)
            need(sum(map(len, self.raws.values())) + len(raw) <= MAX_TOTAL, "input total byte bound")
            self.raws[row["path"]] = raw
        raw = self.raws[row["path"]]
        need(a.pin(raw)["sha256"] == row["sha256"], "input checksum mismatch: " + row["path"])
        self.pins[row["path"]] = a.pin(raw)
        return raw

    def json(self, row):
        return a.decode(self.read(row))

    def recheck(self):
        for name, raw in self.raws.items():
            need(a.read(self.root / name) == raw, "input changed during import: " + name)


def selected(reader, spec):
    b.pins.fields(spec, ("file", "select"))
    value = reader.json(spec["file"])
    keys = spec["select"]
    need(type(keys) is list and len(keys) <= 8 and all(type(k) is str and 0 < len(k) <= 128 for k in keys),
         "bounded explicit JSON object selection required")
    for key in keys:
        need(type(value) is dict and key in value, "selected retained metadata object missing: " + key)
        value = value[key]
    return value


def rows(value):
    if type(value) is dict:
        value = list(value.values())
    need(type(value) is list and len(value) <= b.MAX_PACKAGES, "bounded retained package records required")
    need(all(type(row) is dict for row in value), "retained package records must be objects")
    return value


def identity(row):
    projected = dict(name=row.get("name"), version=row.get("version"), arch="any", sha256=row.get("sha256"))
    b.s.identity(projected)
    return row["name"], row["version"], row["sha256"]


def pkginfo(metadata, checksum, buildinfo=None, members=None):
    def one(key):
        values = metadata.get(key)
        need(type(values) is list and len(values) == 1, "singleton PKGINFO " + key + " required")
        return values[0]
    row = dict(name=one("pkgname"), version=one("pkgver"), arch=one("arch"), sha256=checksum,
               depends=metadata.get("depend", []), provides=metadata.get("provides", []),
               conflicts=metadata.get("conflict", []), replaces=metadata.get("replaces", []),
               license=metadata.get("license", []), source_url=metadata.get("url", []))
    if "pkgbase" in metadata:
        row["pkgbase"] = one("pkgbase")
    row["retained_pkginfo"] = metadata
    if buildinfo is not None:
        row["retained_buildinfo"] = buildinfo
    if members is not None:
        row["retained_members"] = members
    return row


def archive_metadata(raw):
    """Inspect metadata members only; no payload extraction or execution."""
    metadata, buildinfo, members, expanded = None, None, [], 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r|*") as archive:
        for member in archive:
            need(len(members) < MAX_MEMBERS, "archive member count bound")
            name = c.clean_name(member.name)
            need(name not in members, "duplicate archive member")
            members.append(name)
            need(member.size >= 0, "negative archive size")
            expanded += member.size
            need(expanded <= c.MAX_TOTAL, "archive declared byte bound")
            if name in (".PKGINFO", ".BUILDINFO"):
                need(member.isfile() and member.size <= 1024**2, "bounded regular package metadata required")
                value = c.metadata(archive.extractfile(member).read().decode("utf-8"))
                if name == ".PKGINFO": metadata = value
                else: buildinfo = value
    need(metadata is not None, "archive PKGINFO missing")
    return pkginfo(metadata, a.pin(raw)["sha256"], buildinfo, members)


def validate_metadata(row):
    name, version, checksum = identity(row)
    b.s.identity(dict(name=name, version=version, arch=row.get("arch"), sha256=checksum))
    need(type(version) is str and a.VERSION.fullmatch(version), "bounded package version required")
    for key in ("depends", "provides", "conflicts", "replaces"):
        need(key in row, "unknown retained metadata field: " + key)
        b.relations(row[key], provides=(key == "provides"))
    for key in ("license", "source_url"):
        values = row.get(key, [])
        need(type(values) is list and len(values) <= 256 and all(type(x) is str and 0 < len(x) <= 2048 and x.isprintable() for x in values),
             "bounded retained " + key + " declaration required")
    if "pkgbase" in row:
        b.name(row["pkgbase"])
    return row


def recipe_projection(reader, spec):
    b.pins.fields(spec, ("package", "path", "files"))
    name = b.name(spec["package"])
    parts = b.s.relative(spec["path"])
    need(parts[-1] == "PKGBUILD", "explicit reviewed PKGBUILD required")
    need(type(spec["files"]) is dict and "PKGBUILD" in spec["files"] and len(spec["files"]) <= 256,
         "complete reviewed recipe file hashes required")
    base = reader.root.joinpath(*parts[:-1])
    # Refuse undeclared trees before the shared auditor recursively hashes them.
    pending, actual, entries = [base], set(), 0
    while pending:
        directory = pending.pop()
        need(not directory.is_symlink() and directory.is_dir(), "ordinary recipe directories required")
        with os.scandir(directory) as children:
            for child in children:
                entries += 1
                need(entries <= MAX_FILES, "recipe namespace entry bound")
                mode = child.stat(follow_symlinks=False).st_mode
                if stat.S_ISDIR(mode): pending.append(Path(child.path))
                else:
                    need(stat.S_ISREG(mode), "ordinary nonsymlink recipe inputs required")
                    actual.add(Path(child.path).relative_to(base).as_posix())
    need(actual == set(spec["files"]), "recipe namespace/hash mismatch")
    for relative, checksum in spec["files"].items():
        rel = b.s.relative(relative)
        reader.read(dict(path="/".join((*parts[:-1], *rel)), sha256=checksum))
    report = c.recipe(base / "PKGBUILD")
    need(report["input_sha256"] == spec["files"], "recipe namespace/hash mismatch")
    need(all(error.startswith("unsafe/missing local source: ") for error in report["errors"]),
         "recipe static audit failed: " + "; ".join(report["errors"]))
    data = d.normalize_metadata(report["metadata"])
    need(data["pkgname"] == [name], "recipe binary name mismatch")
    version = data["pkgver"][0] + "-" + data["pkgrel"][0]
    if data["epoch"][0] != "0": version = data["epoch"][0] + ":" + version
    sources = []
    for url, checksum in zip(data["source"], data["sha256sums"]):
        url = url.split("::", 1)[-1]
        if url.startswith("git+"):
            sources.append(dict(url=url, commit=url.rsplit("#commit=", 1)[-1]))
        else:
            if "://" not in url:
                b.s.relative(url)
            sources.append(dict(url=url if "://" in url else "local:" + url, sha256=checksum))
    source = dict(id=data["pkgbase"][0], recipe_sha256=spec["files"]["PKGBUILD"], sources=sources)
    b.pins.project(dict(package=dict(name=name, version=version, arch=data["arch"][0]), **{k:source[k] for k in ("recipe_sha256", "sources")}))
    return data, version, source, report


def import_graph(selection, reader):
    b.pins.fields(selection, ("schema_version", "release_id", "snapshot_id", "inventory", "manifest", "extension_profile",
                              "metadata", "archives", "recipes", "changed"))
    need(type(selection["schema_version"]) is int and selection["schema_version"] == 1, "unsupported import selection schema")
    expected = v.inventory(reader.read(selection["inventory"]))
    need(0 < len(expected) <= b.MAX_PACKAGES, "bounded nonempty pre-change inventory required")
    manifest = reader.json(selection["manifest"])
    need(type(manifest) is dict and type(manifest.get("projects")) is list, "retained release manifest with explicit project set required")
    authority_rows = rows(manifest.get("packages"))
    project_claims = [identity(row) for row in rows(manifest["projects"])]
    if selection["extension_profile"] is not None:
        extension = reader.json(selection["extension_profile"])
        need(type(extension) is dict and type(extension.get("incoming")) is dict, "retained extension incoming map required")
        incoming = rows(extension["incoming"])
        need(set(extension["incoming"]) == {identity(row)[0] for row in incoming}, "extension map/name mismatch")
        authority_rows += incoming
        project_claims.extend(identity(row) for row in incoming)
    authority = {}
    for row in authority_rows:
        name, version, checksum = identity(row)
        if expected.get(name) != version: continue
        need(name not in authority or authority[name]["sha256"] == checksum, "ambiguous same-version release archive: " + name)
        authority[name] = row
    need(set(authority) == set(expected), "release archive authority does not cover exact inventory")
    project_names = {name for name, version, checksum in project_claims
                     if name in authority and version == expected[name] and checksum == authority[name]["sha256"]}
    records, claims, skipped = {}, {}, []

    def add(row, origin):
        name, version, checksum = identity(row)
        if expected.get(name) != version:
            skipped.append(dict(name=name, version=version, input=origin, reason="OUTSIDE_SELECTED_INVENTORY_VERSION"))
            return
        need(authority[name]["sha256"] == checksum, "metadata/release archive hash mismatch: " + name)
        row = validate_metadata(row)
        projection = {k: row.get(k) for k in ("name", "version", "arch", "depends", "provides", "conflicts", "replaces", "license")}
        if name in records:
            other = {k: records[name].get(k) for k in projection}
            need(a.encoded(projection) == a.encoded(other), "conflicting retained package metadata: " + name)
            for key in ("pkgbase", "retained_pkginfo", "retained_buildinfo", "retained_members"):
                if key in row:
                    need(key not in records[name] or a.encoded(records[name][key]) == a.encoded(row[key]),
                         "conflicting retained " + key + ": " + name)
                    records[name][key] = row[key]
        else: records[name] = row
        declarations = {key:row[key] for key in ("pkgbase", "license", "source_url", "url", "filename", "signature_sha256") if key in row}
        claims.setdefault(name, []).append(dict(**origin, declarations=declarations))

    need(type(selection["metadata"]) is list and len(selection["metadata"]) <= 64, "bounded metadata sources required")
    for spec in selection["metadata"]:
        b.pins.fields(spec, ("file", "select", "format"))
        value = selected(reader, {key:spec[key] for key in ("file", "select")})
        need(spec["format"] in ("lock", "pkginfo"), "unsupported retained metadata format")
        for row in rows(value):
            if spec["format"] == "pkginfo":
                meta = row.get("metadata")
                need(type(meta) is dict, "retained PKGINFO report metadata required")
                if ".PKGINFO" in meta:
                    row = pkginfo(meta[".PKGINFO"], row.get("sha256"), meta.get(".BUILDINFO"), row.get("members"))
                else: row = pkginfo(meta, row.get("sha256"))
            add(row, dict(path=spec["file"]["path"], select=spec["select"], format=spec["format"]))
    need(type(selection["archives"]) is list and len(selection["archives"]) <= 128, "bounded explicit archive metadata inputs required")
    for spec in selection["archives"]:
        add(archive_metadata(reader.read(spec)), dict(path=spec["path"], format="ARCHIVE_METADATA_ONLY"))
    recipe_results = {}
    need(type(selection["recipes"]) is list and len(selection["recipes"]) <= 128, "bounded explicit recipe inputs required")
    for spec in selection["recipes"]:
        name = spec.get("package")
        need(name in project_names and name not in recipe_results, "recipe requires unique explicit project package membership")
        recipe_results[name] = recipe_projection(reader, spec)
    sources, builds, packages, inventory, review = {}, [], [], [], []
    for name, version in sorted(expected.items()):
        reasons, recipe = [], recipe_results.get(name)
        if name not in project_names and any(claim[0] == name for claim in project_claims):
            reasons.append("PROJECT_RELEASE_MEMBERSHIP_UNBOUND")
        meta = records.get(name)
        if meta is None and recipe:
            # Source-only metadata can bridge a retained project manifest, but
            # cannot become an archive correspondence/build success.
            data, recipe_version, source, report = recipe
            need(recipe_version == version, "recipe/release version mismatch: " + name)
            raw = next((row for row in manifest["projects"] if row["name"] == name and row["version"] == version
                        and row["sha256"] == authority[name]["sha256"]), None)
            need(raw is not None and all(sorted(raw.get(key, [])) == sorted(data[field]) for key, field in (("depends", "depends"), ("provides", "provides"), ("conflicts", "conflicts"))),
                 "recipe/retained project manifest relation mismatch: " + name)
            meta = dict(name=name, version=version, sha256=authority[name]["sha256"], arch=data["arch"][0],
                        depends=raw["depends"], provides=raw["provides"], conflicts=raw["conflicts"],
                        replaces=data["replaces"], license=data["license"], pkgbase=data["pkgbase"][0], source_url=[])
            validate_metadata(meta)
            claims[name] = [dict(path=report["recipe"], format="REVIEWED_RECIPE_AND_RETAINED_PROJECT_RELATIONS_SOURCE_ONLY")]
            reasons.append("ARCHIVE_METADATA_CORRESPONDENCE_UNVERIFIED")
        need(meta is not None, "missing package metadata/architecture; cannot fabricate inventory: " + name)
        origin = "PROJECT_RELEASE_RECORD" if name in project_names else "EXTERNAL_RETAINED_ARM_PACKAGE"
        package = dict(name=name, version=version, arch=meta["arch"], depend=meta["depends"], provides=meta["provides"],
                       conflicts=meta["conflicts"], replaces=meta["replaces"], origin=origin, sha256=authority[name]["sha256"])
        if "pkgbase" in meta: package["pkgbase"] = meta["pkgbase"]
        packages.append(package)
        inv = {k:package[k] for k in ("name", "version", "arch", "provides", "origin")}
        if "pkgbase" in meta: inv["pkgbase"] = meta["pkgbase"]
        inventory.append(inv)
        binding_errors = None
        if recipe:
            data, recipe_version, source, report = recipe
            if report["errors"]:
                reasons.append("DECLARED_LOCAL_SOURCE_NOT_AVAILABLE")
            need(recipe_version == version and data["arch"] == [meta["arch"]], "recipe package identity differs: " + name)
            for key, field in (("depends", "depends"), ("provides", "provides"), ("conflicts", "conflicts"), ("replaces", "replaces"), ("license", "license")):
                need(sorted(meta.get(key, [])) == sorted(data[field]), "recipe/package metadata differs: " + name + ":" + key)
            if "pkgbase" in meta: need(meta["pkgbase"] == source["id"], "recipe/package pkgbase differs: " + name)
            bound = False
            if "retained_buildinfo" in meta and "retained_pkginfo" in meta and "retained_members" in meta:
                errors = d.bind_artifact(report["metadata"], dict(metadata={".PKGINFO":meta["retained_pkginfo"], ".BUILDINFO":meta["retained_buildinfo"]}, members=meta["retained_members"]), source["recipe_sha256"])
                binding_errors = errors
                bound = not errors
                if errors: reasons.append("RECIPE_ARCHIVE_BINDING_UNVERIFIED")
            else: reasons.append("RECIPE_ARCHIVE_BINDING_UNVERIFIED")
            reasons.append("IMPLICIT_TOOLCHAIN_INPUTS_UNKNOWN")
            need(source["id"] not in sources or sources[source["id"]] == source, "conflicting source build unit")
            sources[source["id"]] = source
            builds.append(dict(package=name, source_id=source["id"], makedepend=data["makedepends"],
                               checkdepend=data["checkdepends"], toolchain=[], disposition="hold", owner=None,
                               hold_reason=";".join(sorted(set(reasons)))))
        else:
            bound = False
            reasons += ["BUILD_DEPENDENCY_METADATA_UNKNOWN", "SOURCE_RECIPE_PINS_UNKNOWN"]
            # Omit unknown build metadata, instead of declaring empty make,
            # check or toolchain inputs. The frozen planner holds and expands
            # its conservative coverage review for these exact missing rows.
        reasons += ["PACKAGE_OWNER_UNKNOWN", "ARM_AFFECTEDNESS_AND_FIX_UNKNOWN"]
        review.append(dict(name=name, version=version, archive_sha256=authority[name]["sha256"], origin=origin,
                           external=name not in project_names, metadata_inputs=claims[name],
                           pkgbase=meta.get("pkgbase"), archive_recipe_metadata_bound=bound,
                           archive_recipe_binding_errors=binding_errors,
                           recipe_static_errors=recipe[3]["errors"] if recipe else None,
                           project_build_status="NOT_ESTABLISHED_BY_IMPORT" if name in project_names else "EXTERNAL_NOT_PROJECT_BUILT",
                           license_declarations=meta.get("license", []), upstream_url_declarations=meta.get("source_url", []),
                           source_license_provenance="NOT_AUTHENTICATED_BY_IMPORT", holds=sorted(set(reasons))))
    graph = dict(schema_version=1, metadata_role="pre-change-release", release_id=b.text(selection["release_id"]),
                 snapshot_id=b.text(selection["snapshot_id"]), packages=packages, sources=[sources[key] for key in sorted(sources)],
                 build_dependencies=builds, changed=selection["changed"],
                 capacity=dict(native_aarch64_slots=None, owner=None, reference=None))
    a.inventory(inventory)
    b.plan(graph)
    reader.recheck()
    return dict(schema_version=1, status="RETAINED_INPUT_GRAPH_IMPORT_REQUIRES_REVIEW", graph=graph, inventory=inventory,
                packages=review, skipped_metadata=skipped, inputs=reader.pins,
                summary=dict(packages=len(inventory), external=sum(r["external"] for r in review),
                             project=len(project_names), reviewed_recipes=len(builds),
                             archive_recipe_metadata_bound=sum(r["archive_recipe_metadata_bound"] for r in review),
                             holds=dict(Counter(reason for row in review for reason in row["holds"]))),
                global_holds=["ONGOING_OWNERS_AND_NATIVE_BUILD_CAPACITY_UNKNOWN", "ADVISORY_AND_ARM_FIX_EVIDENCE_NOT_SUPPLIED"],
                limitations=["Digest binding does not authenticate archive signatures, origin or release admission.",
                             "Archive/recipe metadata correspondence is source evidence, not a native build or maintained update.",
                             "External ARM packages are never promoted to project-built packages by a matching local name/version.",
                             "Missing external build metadata stays omitted and causes conservative frozen-planner coverage holds.",
                             "Recipe toolchain=[] is an explicit held unknown, not an assertion that no implicit toolchain is needed.",
                             "License and upstream URL declarations do not establish corresponding source/license closure.",
                             "No network, actors, build, installation, source mutation, signing or publication executes."])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="root for explicitly selected local DATA/recipe paths")
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--selection-sha256", required=True)
    parser.add_argument("--output", choices=("bundle", "graph", "inventory"), default="bundle")
    args = parser.parse_args(argv)
    try:
        raw = a.read(args.selection)
        need(a.pin(raw)["sha256"] == args.selection_sha256, "selection checksum mismatch")
        result = import_graph(a.decode(raw), Reader(args.root.absolute()))
        result["selection"] = a.pin(raw)
        need(a.read(args.selection) == raw, "selection changed during import")
        sys.stdout.write(b.pins.encoded(result if args.output == "bundle" else result[args.output]).decode())
        return 0
    except (b.r.Error, b.s.Error, OSError, ValueError, TypeError, KeyError, RecursionError,
            tarfile.TarError, EOFError, lzma.LZMAError, zlib.error) as error:
        print("release graph import: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
