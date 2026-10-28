#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded userspace logic fixture for exact KERNEL-C01 allocation code.

This compiles extracted upstream functions, not a kernel or a behavior rewrite.
The cache/slab/mempool/init interfaces are instrumentation stubs: no allocator,
per-CPU concurrency, reclaim, rescuer, I/O, or physical page behavior is tested.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import signal
import stat
import subprocess


SOURCE_COMMIT = "94fb23346d522edf53722357c426a3e58030beea"
PATCH_COMMIT = "0d61333f6e03e8fa4620e33e1bac4c644a9412c6"
SOURCE_PINS = {
    "baseline": "ee6bf72d442a263fc8c86db6048c4476775a860971ba42e1c7cba1e1d693dd27",
    "candidate": "be44b4dcbf65d05c43447f5a37a20a322ed2bf9e06a0f41d9a496bc8ab274dd4",
}
FUNCTION_PINS = {
    "baseline": "2e65bbff2422a95f7ac2ad51636529767a2570e5a39584cedf8a8fb394e20ec6",
    "candidate": "9f693ac1d5106ce9f4ef4a465ebdcb2960136b048910b7184a12bdc07c954137",
    "gfp": "4c589b633ef10f53db0491065a0f765f400562fda37a2e7b679178f59fcb799b",
}
TIMEOUT = 10
FILE_LIMIT = 4 * 1024 * 1024
TOTAL_LIMIT = 16 * 1024 * 1024
RECEIPT_RESERVE = 128 * 1024
DIRECT, IO = 1 << 10, 1 << 6
OPTIMISTIC = (1 << 19) | (1 << 16) | (1 << 13)
CACHE_FLAG = 1 << 23
OTHER_FLAG = 1 << 11

# Stub flag values and geometry match the retained headers, but this is not an
# ABI model. Only the copied functions' branch/argument behavior is exercised.
STUBS = r'''
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned int gfp_t;
typedef uint64_t blk_opf_t;
#define __GFP_DIRECT_RECLAIM (1U << 10)
#define __GFP_IO (1U << 6)
#define __GFP_NOMEMALLOC (1U << 19)
#define __GFP_NORETRY (1U << 16)
#define __GFP_NOWARN (1U << 13)
#define REQ_ALLOC_CACHE (1ULL << 23)
#define OTHER_FLAG (1ULL << 11)
#define BIO_INLINE_VECS 4
#define BIO_MAX_VECS 256
#define unlikely(x) (x)
#define WARN_ON_ONCE(x) warn_once(x)
struct bio_set;
struct block_device { int unused; };
struct bio_vec { int unused; };
struct bio {
    struct bio_set *bi_pool;
    struct block_device *device;
    struct bio_vec *vectors;
    unsigned short nr;
    blk_opf_t opf;
};
struct kmem_cache { int type; };
struct mempool { int initialized, type; };
struct bio_set {
    void *cache;
    struct mempool bio_pool, bvec_pool;
    struct kmem_cache *bio_slab;
    size_t front_pad;
};
struct biovec_slab { unsigned short nr_vecs; struct kmem_cache *slab; };
struct padded_bio { unsigned char pad[16]; struct bio bio; };
static struct padded_bio slab_storage, pool_storage;
static struct bio cached_bio;
static struct bio_vec slab_vectors[256], pool_vectors[256];
static struct kmem_cache bio_slab = {1}, vector_slab = {2};
static struct biovec_slab vector_class = {16, &vector_slab};
static struct block_device device;
static struct {
    int cache_hit, bio_success, bvec_success;
    int warnings, cache_calls, slab_bio, slab_bvec, free_bio;
    int punt, pool_bio, pool_bvec, init_inline, init_standard;
    gfp_t slab_gfp, bvec_gfp, pool_gfp, pool_bvec_gfp;
} state;
static void invariant(int value) { if (!value) abort(); }
static int warn_once(int value) { state.warnings += !!value; return value; }
static int mempool_initialized(struct mempool *p) { return p->initialized; }
static struct bio *bio_alloc_percpu_cache(struct bio_set *bs) {
    invariant(bs->cache != NULL); state.cache_calls++;
    return state.cache_hit ? &cached_bio : NULL;
}
static void *kmem_cache_alloc(struct kmem_cache *slab, gfp_t flags) {
    if (slab == &bio_slab) {
        state.slab_bio++; state.slab_gfp = flags;
        return state.bio_success ? &slab_storage : NULL;
    }
    invariant(slab == &vector_slab);
    state.slab_bvec++; state.bvec_gfp = flags;
    return state.bvec_success ? slab_vectors : NULL;
}
static void kmem_cache_free(struct kmem_cache *slab, void *p) {
    invariant(slab == &bio_slab && p == &slab_storage); state.free_bio++;
}
static struct biovec_slab *biovec_slab(unsigned short nr) {
    invariant(nr >= 5 && nr <= 16); return &vector_class;
}
static void punt_bios_to_rescuer(struct bio_set *bs) {
    invariant(bs->bio_pool.initialized); state.punt++;
}
static void *mempool_alloc(struct mempool *pool, gfp_t flags) {
    invariant(pool->initialized && (flags & __GFP_DIRECT_RECLAIM));
    if (pool->type == 1) {
        state.pool_bio++; state.pool_gfp = flags; return &pool_storage;
    }
    invariant(pool->type == 2);
    state.pool_bvec++; state.pool_bvec_gfp = flags; return pool_vectors;
}
static void bio_init(struct bio *bio, struct block_device *bdev,
                     struct bio_vec *vec, unsigned short nr, blk_opf_t opf) {
    invariant(bio != NULL); state.init_standard++;
    bio->device = bdev; bio->vectors = vec; bio->nr = nr; bio->opf = opf;
}
static void bio_init_inline(struct bio *bio, struct block_device *bdev,
                            unsigned short nr, blk_opf_t opf) {
    invariant(bio != NULL && nr && nr <= BIO_INLINE_VECS);
    state.init_inline++; bio->device = bdev; bio->nr = nr; bio->opf = opf;
}
'''

DRIVER = r'''
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    struct bio_set bs = {
        .cache = &state, .bio_pool = {1, 1}, .bvec_pool = {1, 2},
        .bio_slab = &bio_slab, .front_pad = offsetof(struct padded_bio, bio)
    };
    unsigned short nr = 1;
    gfp_t gfp = __GFP_IO;
    blk_opf_t opf = 1 | OTHER_FLAG | REQ_ALLOC_CACHE;
    state.bio_success = state.bvec_success = 1;
    const char *test = argv[1];
    if (!strcmp(test, "cache-hit")) { state.cache_hit = 1; nr = 4; }
    else if (!strcmp(test, "cache-miss-slab")) {}
    else if (!strcmp(test, "cache-miss-zero-vec")) { nr = 0; }
    else if (!strcmp(test, "cache-miss-no-reclaim-failure")) { state.bio_success = 0; }
    else if (!strcmp(test, "cache-miss-reclaim-slab")) { gfp |= __GFP_DIRECT_RECLAIM; }
    else if (!strcmp(test, "cache-miss-reclaim-pool")) {
        gfp |= __GFP_DIRECT_RECLAIM; state.bio_success = 0;
    }
    else if (!strcmp(test, "no-cache-slab")) { bs.cache = NULL; }
    else if (!strcmp(test, "large-bvec-success")) { nr = 5; }
    else if (!strcmp(test, "bvec-failure-no-reclaim")) { nr = 5; state.bvec_success = 0; }
    else if (!strcmp(test, "bvec-failure-reclaim")) {
        nr = 5; state.bvec_success = 0; gfp |= __GFP_DIRECT_RECLAIM;
    }
    else if (!strcmp(test, "large-bio-failure-reclaim")) {
        nr = 5; state.bio_success = 0; gfp |= __GFP_DIRECT_RECLAIM;
    }
    else if (!strcmp(test, "invalid-bvec-pool")) { bs.bvec_pool.initialized = 0; }
    else if (!strcmp(test, "zero-vec-no-bvec-pool")) {
        nr = 0; bs.cache = NULL; bs.bvec_pool.initialized = 0;
    }
    else return 2;
    struct bio *bio = bio_alloc_bioset(&device, nr, opf, gfp, &bs);
    int origin = !bio ? 0 : bio == &cached_bio ? 1 :
                 bio == &slab_storage.bio ? 2 : bio == &pool_storage.bio ? 3 : -1;
    invariant(origin >= 0);
    if (bio) invariant(bio->bi_pool == &bs && bio->device == &device);
    int vectors = !bio || !bio->vectors ? 0 : bio->vectors == slab_vectors ? 1 :
                  bio->vectors == pool_vectors ? 2 : -1;
    invariant(vectors >= 0);
    printf("{\"origin\":%d,\"vectors\":%d,\"nr\":%u,\"opf\":%llu,"
           "\"warnings\":%d,\"cache_calls\":%d,\"slab_bio\":%d,\"slab_bvec\":%d,"
           "\"free_bio\":%d,\"punt\":%d,\"pool_bio\":%d,\"pool_bvec\":%d,"
           "\"init_inline\":%d,\"init_standard\":%d,\"slab_gfp\":%u,"
           "\"bvec_gfp\":%u,\"pool_gfp\":%u,\"pool_bvec_gfp\":%u}\n",
           origin, vectors, bio ? bio->nr : 0, (unsigned long long)(bio ? bio->opf : 0),
           state.warnings, state.cache_calls, state.slab_bio, state.slab_bvec,
           state.free_bio, state.punt, state.pool_bio, state.pool_bvec,
           state.init_inline, state.init_standard, state.slab_gfp,
           state.bvec_gfp, state.pool_gfp, state.pool_bvec_gfp);
    return 0;
}
'''


def expected_cases(variant):
    """Independent complete branch observations, including known baseline bug."""
    candidate = variant == "candidate"
    base = dict(origin=0, vectors=0, nr=0, opf=0, warnings=0, cache_calls=0,
                slab_bio=0, slab_bvec=0, free_bio=0, punt=0, pool_bio=0,
                pool_bvec=0, init_inline=0, init_standard=0, slab_gfp=0,
                bvec_gfp=0, pool_gfp=0, pool_bvec_gfp=0)
    flags = 1 | OTHER_FLAG
    result = {}

    def case(name, **updates):
        result[name] = dict(base, **updates)

    case("cache-hit", origin=1, nr=4, opf=flags | CACHE_FLAG,
         cache_calls=1, init_inline=1)
    for name, nr in (("cache-miss-slab", 1), ("cache-miss-zero-vec", 0)):
        case(name, cache_calls=1, **(dict(origin=2, nr=nr, opf=flags | CACHE_FLAG,
             slab_bio=1, slab_gfp=IO, init_inline=int(nr > 0),
             init_standard=int(nr == 0)) if candidate else {}))
    case("cache-miss-no-reclaim-failure", cache_calls=1,
         slab_bio=int(candidate), slab_gfp=IO if candidate else 0)
    case("cache-miss-reclaim-slab", cache_calls=1, nr=1, init_inline=1,
         **(dict(origin=2, opf=flags | CACHE_FLAG, slab_bio=1, slab_gfp=OPTIMISTIC)
            if candidate else dict(origin=3, opf=flags, punt=1, pool_bio=1,
                                   pool_gfp=DIRECT | IO)))
    case("cache-miss-reclaim-pool", cache_calls=1, nr=1, origin=3, opf=flags,
         slab_bio=int(candidate), slab_gfp=OPTIMISTIC if candidate else 0,
         punt=1, pool_bio=1, pool_gfp=DIRECT | IO, init_inline=1)
    case("no-cache-slab", origin=2, nr=1, opf=flags, slab_bio=1,
         slab_gfp=IO, init_inline=1)
    case("large-bvec-success", origin=2, vectors=1, nr=16, opf=flags,
         slab_bio=1, slab_bvec=1, slab_gfp=IO, bvec_gfp=IO, init_standard=1)
    case("bvec-failure-no-reclaim", slab_bio=1, slab_bvec=1, free_bio=1,
         slab_gfp=IO, bvec_gfp=IO)
    case("bvec-failure-reclaim", origin=3, vectors=2, nr=256, opf=flags,
         slab_bio=1, slab_bvec=1, free_bio=1, punt=1, pool_bio=1, pool_bvec=1,
         slab_gfp=OPTIMISTIC, bvec_gfp=OPTIMISTIC, pool_gfp=DIRECT | IO,
         pool_bvec_gfp=DIRECT | IO, init_standard=1)
    case("large-bio-failure-reclaim", origin=3, vectors=2, nr=256, opf=flags,
         slab_bio=1, punt=1, pool_bio=1, pool_bvec=1, slab_gfp=OPTIMISTIC,
         pool_gfp=DIRECT | IO, pool_bvec_gfp=DIRECT | IO, init_standard=1)
    case("invalid-bvec-pool", warnings=1)
    case("zero-vec-no-bvec-pool", origin=2, opf=flags, slab_bio=1,
         slab_gfp=IO, init_standard=1)
    return result


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_regular(path, maximum):
    path = Path(path)
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("bounded regular input required")
    # NONBLOCK prevents a substituted FIFO from stalling before fstat; NOFOLLOW
    # prevents following a substituted final-component symlink.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum or path.is_symlink():
            raise ValueError("bounded regular input required")
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("input byte limit exceeded")
    return data


def extract_function(source, prefix):
    text = source.decode("utf-8")
    if text.count(prefix) != 1:
        raise ValueError("one exact function definition required")
    start = text.index(prefix)
    end = text.index("\n}", start) + 2
    return (text[start:end] + "\n").encode()


def fixture_source(path, variant):
    data = read_regular(path, 128 * 1024)
    if sha(data) != SOURCE_PINS[variant]:
        raise ValueError(f"{variant} block/bio.c pin mismatch")
    allocator = extract_function(data, "struct bio *bio_alloc_bioset(")
    gfp = extract_function(data, "static inline gfp_t try_alloc_gfp(")
    if sha(allocator) != FUNCTION_PINS[variant] or sha(gfp) != FUNCTION_PINS["gfp"]:
        raise ValueError("extracted function pin mismatch")
    notice = data[:data.index(b"#include")]
    header = ("/* Extracted unchanged function bodies from Asahi commit " + SOURCE_COMMIT +
              "; candidate patch " + PATCH_COMMIT + ".\n"
              " * Remaining code is userspace instrumentation, not kernel execution. */\n")
    return notice + header.encode() + STUBS.encode() + gfp + allocator + DRIVER.encode()


def kernel_runtime_plan():
    return {
        "status": "NOT RUN",
        "scope": "separate kernel execution prerequisite before retention",
        "requires": ["reviewed baseline and candidate native kernel builds and matching config",
                     "disposable native ARM runtime with baseline recovery and no production data",
                     "separate reviewed test-only instrumentation; not part of selected eight-line patch"],
        "source_constraints": [
            "bio_alloc_bioset is exported; per-CPU free lists and allocation helpers are private to block/bio.c",
            "an external module alone cannot reliably force or observe cache/slab paths",
            "mempool forward progress requires callers to submit/free each allocation before another",
            "userspace stubs cannot establish IRQ/preemption, rescuer, reclaim or real slab lifetime correctness"],
        "test_design": [
            "review a block/bio.c-local KUnit seam to observe cache/slab/mempool counters with real bioset_init/bio_put",
            "run cache hit and drained cache cases on one pinned CPU; prove the intended path by counters",
            "use scoped test-only allocation fault injection to fail exactly the BIO or bvec slab attempt",
            "assert NULL without reclaim, correct GFP mask and front_pad, bvec cleanup, and REQ_ALLOC_CACHE clearing on mempool fallback",
            "bound each case to ten seconds; unload/destroy owned biosets and verify no outstanding allocations",
            "run both kernels with identical test hooks; keep their config/source/toolchain deltas explicit"],
        "hardware": {"physical_16K": "NOT RUN", "M2_13inch": "NOT RUN", "M2_15inch": "NOT RUN",
                     "required_followup": "boot/recovery, NVMe integrity under pressure, graphics/audio, suspend and paired measurements"},
    }


def limits(file_limit=FILE_LIMIT):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (TIMEOUT, TIMEOUT))
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))


def execute(argv, output, label):
    """Only fixture/compiler process groups; bounded disk logs and reaping."""
    used = sum(p.stat().st_size for p in output.iterdir() if p.is_file())
    # Reserve two logs and compiler output plus the failure receipt. GCC is the
    # pinned trusted tool; input is fixed small C, not an arbitrary source tree.
    file_limit = min(FILE_LIMIT, (TOTAL_LIMIT - RECEIPT_RESERVE - used) // 3)
    if file_limit <= 0:
        raise ValueError("total output byte cap exhausted")
    logs = [output / (label + suffix) for suffix in (".stdout", ".stderr")]
    info = {"argv": [str(x) for x in argv], "returncode": None,
            "status": "FAIL", "timeout_seconds": TIMEOUT, "file_bytes": file_limit}
    try:
        with logs[0].open("xb") as stdout, logs[1].open("xb") as stderr:
            proc = None
            mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})

            def child_setup():
                limits(file_limit)
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)

            try:
                proc = subprocess.Popen(argv, cwd=output, stdin=subprocess.DEVNULL,
                                        stdout=stdout, stderr=stderr, start_new_session=True,
                                        preexec_fn=child_setup,
                                        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC",
                                             "HOME": str(output), "TMPDIR": str(output)})
                # A deferred parent handler may raise here. proc is already
                # tracked and the except branch can reap its process group.
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)
                code = proc.wait(timeout=TIMEOUT)
            except BaseException:
                signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
                if proc is not None:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    info["returncode"] = proc.wait(timeout=TIMEOUT)
                raise
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        info["returncode"] = code
        if code != 0:
            raise RuntimeError(f"{label} returned {code}; review retained bounded logs")
        info["status"] = "PASS"
    except BaseException as error:
        info["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        info["logs"] = {p.name: {"bytes": p.stat().st_size,
                        "sha256": sha(read_regular(p, file_limit))} for p in logs if p.is_file()}
        (output / (label + ".command.json")).write_text(json.dumps(info, sort_keys=True) + "\n")
    return info, read_regular(logs[0], FILE_LIMIT)


def new_output(output, evidence_root):
    output, root = Path(output), Path(evidence_root)
    if not output.is_absolute() or not root.is_absolute() or root.resolve() != root:
        raise ValueError("canonical absolute evidence paths required")
    if root.is_symlink() or output.exists() or output.is_symlink():
        raise ValueError("new output and regular evidence root required")
    if output.parent.resolve() != output.parent or not output.is_relative_to(root) or output == root:
        raise ValueError("output must be a new canonical child of owned evidence root")
    return output


def run_fixture(baseline_bio, candidate_bio, output, compiler, compiler_sha256,
                evidence_root=None):
    """CLI/import interface; requires exact inputs and compiler pin, no Makefile."""
    if os.name != "posix" or platform.system() != "Linux":
        raise ValueError("Linux process/resource bounds required")
    root = (Path(__file__).resolve().parents[3] / "artifacts/kernel-native-stage/regression"
            if evidence_root is None else Path(evidence_root))
    output = new_output(output, root)
    sources = {v: fixture_source(p, v) for v, p in
               (("baseline", baseline_bio), ("candidate", candidate_bio))}
    compiler = Path(compiler)
    if not compiler.is_absolute() or compiler.resolve() != compiler or not os.access(compiler, os.X_OK):
        raise ValueError("canonical absolute executable compiler required")
    if sha(read_regular(compiler, 128 * 1024 * 1024)) != compiler_sha256:
        raise ValueError("compiler SHA-256 mismatch")
    output.mkdir(parents=True, mode=0o700)
    report = {"schema_version": 1, "status": "FAIL", "evidence_kind": "userspace-extracted-C-logic-fixture",
              "execution_arch": platform.machine(), "actual_kernel_execution": "NOT RUN",
              "source_commit": SOURCE_COMMIT, "patch_commit": PATCH_COMMIT,
              "source_license": "GPL-2.0 SPDX; unchanged Jens Axboe copyright retained in generated fixtures",
              "source_pins": SOURCE_PINS, "function_pins": FUNCTION_PINS,
              "compiler": {"path": str(compiler), "sha256": compiler_sha256},
              "limits": {"command_seconds": TIMEOUT, "file_bytes": FILE_LIMIT,
                         "total_output_bytes": TOTAL_LIMIT, "virtual_memory_bytes": 512 * 1024 * 1024},
              "commands": [], "variants": {}, "kernel_runtime_plan": kernel_runtime_plan()}
    interruption = None
    try:
        for variant in ("baseline", "candidate"):
            source, executable = output / (variant + ".c"), output / variant
            source.write_bytes(sources[variant])
            command, _ = execute([str(compiler), "-std=gnu11", "-O2", "-Wall", "-Wextra",
                                  "-Werror=implicit-function-declaration", "-fno-strict-aliasing",
                                  str(source), "-o", str(executable)], output, variant + "-compile")
            report["commands"].append(command)
            report["variants"][variant] = {"fixture_sha256": sha(sources[variant]),
                                           "executable_sha256": sha(read_regular(executable, FILE_LIMIT)),
                                           "cases": {}}
            for name, expected in expected_cases(variant).items():
                command, raw = execute([str(executable), name], output, variant + "-" + name)
                report["commands"].append(command)
                observed = json.loads(raw)
                report["variants"][variant]["cases"][name] = {
                    "status": "PASS" if observed == expected else "FAIL",
                    "expected": expected, "observed": observed}
                if observed != expected:
                    raise RuntimeError(f"{variant}/{name} observation mismatch")
            if sum(p.stat().st_size for p in output.iterdir() if p.is_file()) > TOTAL_LIMIT:
                raise ValueError("total output byte cap exceeded")
        report["regression_demonstrated"] = {
            "baseline_criterion": "EXPECTED FAILURE reproduced in userspace logic fixture",
            "candidate_criterion": "PASS in userspace logic fixture",
            "baseline_empty_cache_nonreclaim": "NULL with no slab attempt",
            "candidate_empty_cache_nonreclaim": "slab attempt succeeds; REQ_ALLOC_CACHE retained",
            "actual_kernel_execution": "NOT RUN"}
        report["status"] = "PASS"
    except BaseException as error:
        report["status"] = "FAIL"
        report["error"] = type(error).__name__ + ": " + str(error)
        if not isinstance(error, Exception):
            report["cancelled"] = not isinstance(error, SystemExit)
            interruption = error
    receipt = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    if len(receipt) > RECEIPT_RESERVE:
        raise ValueError("fixture receipt cap exceeded")
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
    try:
        (output / "result.json").write_bytes(receipt)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
    if interruption is not None:
        raise interruption
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("baseline-bio", "candidate-bio", "output", "compiler", "compiler-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--evidence-root")
    args = parser.parse_args()
    report = run_fixture(args.baseline_bio, args.candidate_bio, args.output,
                         args.compiler, args.compiler_sha256, args.evidence_root)
    print(json.dumps({"status": report["status"], "execution_arch": report["execution_arch"],
                      "actual_kernel_execution": "NOT RUN", "result": str(Path(args.output) / "result.json")}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
