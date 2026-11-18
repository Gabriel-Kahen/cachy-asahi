# SPDX-License-Identifier: MIT
"""First Qt family pair callbacks for the existing private hosted owner."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
FAMILY = "scripts/ci/qt612-complete-family-native-source"
DOCKER = "/usr/bin/docker"
COMPONENT = "gui_server"
LABEL = "org.cachy-asahi.qt612-reference.nonce"
SOCKET_ENV = "QT612_HOSTED_OWNED_DOCKER_SOCKET"
CREDENTIAL_API = "ROOT_QT612_STAGE_LIFECYCLE_CREDENTIAL_V1"


def need(condition, message):
    if not condition:
        raise ValueError(message)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def private_socket(value):
    need(type(value) is str and re.fullmatch(r"/[A-Za-z0-9_./-]+/volume/docker\.sock", value),
         "Exact owned Docker socket path required")
    path = Path(value)
    need(path == path.resolve(strict=True) and str(path) == value, "Ordinary owned Docker socket path required")
    info = path.stat()
    need(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0 and info.st_gid == os.getgid()
         and stat.S_IMODE(info.st_mode) == 0o660, "Private daemon socket ownership differs")
    return path, (info.st_dev, info.st_ino)


def build_child():
    """Run the whole pinned builder against the selected local socket only."""
    need(sys.flags.isolated and __debug__ and os.getuid() == os.geteuid() > 0,
         "Isolated ordinary family builder required")
    endpoint, identity = private_socket(os.environ.get(SOCKET_ENV))
    source = Path(os.environ["QT612_FAMILY_SOURCE_ROOT"])
    program = source / "runtime/gui_server/scripts/build/build_family.py"
    need(len(sys.argv) > 2 and sys.argv[1] == str(program), "Exact GUI server build program required")
    sys.argv = sys.argv[1:]
    pipeline = load(source / FAMILY / "pipeline.py", "qt612_hosted_child_pipeline")
    binding = pipeline.require_actual_family(COMPONENT, actor_argv=sys.argv[1:])
    image, nonce = binding["image"], binding["nonce"]
    name = "cachy-qt612-family-" + nonce + "-gui_server-" + os.environ["CACHY_QT612_REFERENCE_ATTEMPT"]

    def docker(args, allowed):
        need(args[0] == "docker" and args[1:] in allowed, "Unexpected maintained builder Docker query")
        need(private_socket(str(endpoint))[1] == identity, "Same owned socket required")
        return [DOCKER, "--host=unix://" + str(endpoint), *args[1:]]

    class BuildDocker:
        SubprocessError = subprocess.SubprocessError
        TimeoutExpired = subprocess.TimeoutExpired

        @staticmethod
        def check_output(args, **kwargs):
            allowed = (["image", "inspect", image], ["info", "--format", "{{.Architecture}}"])
            return subprocess.check_output(docker(args, allowed), **kwargs)

        @staticmethod
        def run(args, **kwargs):
            # The maintained builder has a force-removal timeout fallback.
            # The owned controller handles deadlines and retirement in this route.
            required = ("--rm", "--pull=never", "--read-only", "--security-opt=no-new-privileges",
                        "--cap-drop=ALL")
            options = {"--network": "none", "--platform": "linux/arm64", "--cpus": "1", "--memory": "4g",
                       "--memory-swap": "4g", "--pids-limit": "512", "--tmpfs": "/tmp:rw,nosuid,nodev,exec,size=4g",
                       "--user": f"{os.getuid()}:{os.getgid()}"}
            need(args[:4] == ["docker", "run", "--rm", "--name"] and args[4] == name
                 and args[-3:] == ["/bin/bash", image, "/builder-entry.sh"]
                 and all(token in args for token in required)
                 and all(args.count(key) == 1 and args[args.index(key)+1] == value
                         for key, value in options.items()), "Exact owned offline GUI container required")
            return subprocess.run(docker(args, (args[1:],)), **kwargs)

    module = load(program, "qt612_hosted_builder")
    module.subprocess = BuildDocker
    return module.main()


def write_fresh(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)


def qualifier_command(*, source, output, scratch, inventory, image, nonce, request_sha256):
    """Preserve the request's absolute paths in a separate owned container."""
    program = source/FAMILY/"qualify.py"
    request = output/"qualifier-input/request.json"
    mounts = [(source, "readonly"), (output, "readonly"), (scratch, None)]
    if not inventory.is_relative_to(source):
        mounts.append((inventory, "readonly"))
    need(not any("," in str(path) or "\n" in str(path) for path, _ in mounts),
         "Unambiguous isolated qualifier mounts required")
    args = ["run", "--rm", "--pull=never", "--platform=linux/arm64", "--network=none", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--cpus=1", "--memory=2g",
            "--memory-swap=2g", "--pids-limit=128", "--workdir=/",
            "--user", f"{os.getuid()}:{os.getgid()}", "--name", "cachy-qt612-qualify-"+nonce]
    for path, mode in mounts:
        args += ["--mount", f"type=bind,src={path},dst={path}" + (f",{mode}" if mode else "")]
    return args + ["--entrypoint=/usr/bin/python3", image, "-I", "-B", str(program),
                   "--request", str(request), "--request-sha256", request_sha256]


class FirstPairExecutor:
    """Run the exact builds and comparison using the retained 349 owner's command runner."""

    API = "ROOT_QT612_COMPLETE_FAMILY_OWNED_EXECUTOR_V1"

    def __init__(self, pipeline, plan, owner_commands, supervisor, *, socket, source, binding, binding_sha256,
                 lifecycle_credential=None):
        need(plan["component"] == COMPONENT and plan["serial"] is True, "Select the first serial family pair")
        self.pipeline = pipeline
        self.plan = plan
        self.commands = owner_commands
        self.supervisor = supervisor
        self.lifecycle_credential = lifecycle_credential
        self.source = Path(source)
        self.endpoint, self.socket_identity = private_socket(str(socket))
        self.host_option = "--host=unix://" + str(self.endpoint)
        self.env = {
            SOCKET_ENV: str(self.endpoint),
            "QT612_FAMILY_SOURCE_ROOT": str(source),
            "QT612_FAMILY_SOURCE_MAP_SHA256": plan["source_map_sha256"],
            "QT612_FAMILY_BINDING_PATH": str(binding),
            "QT612_FAMILY_BINDING_SHA256": binding_sha256,
            "DOCKER_HOST": "unix://" + str(self.endpoint),
            "DOCKER_BUILDKIT": "0",
        }
        # Commands starts with a scrubbed environment. Forward only the actual
        # Actions identity fields already read by the maintained binding.
        for key in ("GITHUB_REPOSITORY", "GITHUB_EVENT_NAME", "GITHUB_SHA", "GITHUB_REF",
                    "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
            self.env[key] = os.environ[key]
        self.authenticated = self.domain_verified = self.inventory_verified = False
        self.attempt = 0
        self.absence_confirmed = True
        self.compared = False
        self.executions = []
        self.absence = {}

    def authenticate_Root_stage_binding(self, binding):
        self.supervisor.authenticate_Root_stage_binding(binding)
        self.binding = binding
        if self.lifecycle_credential is not None:
            need(getattr(self.lifecycle_credential, "API", None) == CREDENTIAL_API,
                 "Exact separately authenticated lifecycle credential interface required")
            self.lifecycle_credential.authenticate_stage(binding)
        self.authenticated = True

    def require_domain(self, policy):
        need(self.authenticated, "Authenticate the same-run Root binding first")
        self.supervisor.require_domain(policy)
        self.domain_verified = True

    def require_signed_inventory(self, **expected):
        need(self.domain_verified and expected["component"] == COMPONENT
             and expected["image"] == self.plan["image"] and expected["inventory_pin"] == self.plan["inventory_pin"]
             and expected["signature_policy"] == "Required TrustedOnly" and expected["previous_providers"] == [],
             "Same authenticated signed inventory and stage domain required")
        self.supervisor.require_signed_inventory(**expected)
        result = self.docker("image", "inspect", self.plan["image"])
        rows = json.loads(result.stdout)
        need(len(rows) == 1 and rows[0]["Id"] == self.plan["image"]
             and rows[0]["Os"] == "linux" and rows[0]["Architecture"] == "arm64"
             and (rows[0]["Config"]["Labels"] or {}).get(LABEL) == self.plan["nonce"],
             "Same fresh aarch64 stage image on the dedicated daemon required")
        self.inventory_verified = True

    def docker(self, *args, seconds=8):
        need(self.domain_verified and private_socket(str(self.endpoint))[1] == self.socket_identity,
             "Same authenticated scoped daemon socket required")
        return self.commands([DOCKER, self.host_option, *args], seconds)

    def require_no_containers(self):
        need(self.inventory_verified, "Authenticate inventory before container checks")
        result = self.docker("container", "ls", "-a", "--no-trunc", "--quiet")
        need(result.stdout == b"", "The dedicated daemon must have no containers")
        return self.retired(result, result.args)

    def require_absent_twice(self, name):
        expected = "cachy-qt612-family-" + self.plan["nonce"] + "-gui_server-" + str(self.attempt)
        need(self.attempt in (1, 2) and name == expected and not self.absence_confirmed,
             "Check absence of the exact completed attempt")
        observations = []
        for _ in range(2):
            result = self.docker("container", "ls", "-a", "--no-trunc", "--quiet", "--filter", "name=^/" + name + "$")
            need(result.stdout == b"", "Owned GUI build container remains on the daemon")
            observations.append(self.retired(result, result.args))
        self.absence["build-"+str(self.attempt)] = observations
        self.absence_confirmed = True

    def retired(self, result, argv):
        row = self.commands.rows[-1]
        need(row["argv"] == argv, "Same naturally retired command record required")
        record = row["retirement"]
        need(result.returncode == record["exit"] == 0 and record["reaped"] is True
             and record["ownership"] == "REAPED" and record["group_census"] == "EMPTY_TWICE"
             and record["output_complete"] is True and not record["signals"] and not record["timeout"]
             and record["error"] is None, "Natural complete hosted command retirement required")
        return dict(index=len(self.commands.rows)-1, argv=argv, retirement=record,
                    stdout=dict(bytes=len(result.stdout), sha256=hashlib.sha256(result.stdout).hexdigest()),
                    stderr=dict(bytes=len(result.stderr), sha256=hashlib.sha256(result.stderr).hexdigest()))

    def run(self, argv, seconds, *, env, stdout=None):
        need(self.inventory_verified and self.absence_confirmed and not self.compared,
             "Authenticate inputs and confirm retirement before the next command")
        if self.attempt < 2:
            row = self.plan["builds"][self.attempt]
            need(argv == row["argv"] and env == row["env"] and stdout is None
                 and seconds == self.pipeline.BUILD_SECONDS, "Run the exact next serial family build")
            launch = [*argv[:3], str(HERE / "executor.py"), *argv[3:]]
        else:
            destination = Path(self.plan["builds"][0]["argv"][-1]).parent / "comparison.json"
            need(argv == self.plan["compare"] and env == {} and stdout == str(destination)
                 and seconds == self.pipeline.COMPARE_SECONDS, "Run the exact strict family comparison")
            launch = argv
        result = self.commands(launch, seconds, env={**self.env, **env})
        self.executions.append(self.retired(result, launch))
        if stdout is None:
            self.attempt += 1
            self.absence_confirmed = False
        else:
            write_fresh(destination, result.stdout)
            self.compared = True
        return dict(exit=0, natural=True, reaped=True, output_complete=True)

    def qualify(self, *, argv, timeout, memory_bytes, cpus, output_json):
        need(self.compared and len(self.executions) == 3 and timeout == self.pipeline.QUALIFY_SECONDS
             and memory_bytes == 2*1024**3 and cpus == 1, "Strict comparison and bounded qualifier domain required")
        C, M = self.pipeline.C, self.pipeline.C.M
        output = M.ordinary(Path(self.plan["builds"][0]["argv"][-1]).parent)
        request_path = output/"qualifier-input/request.json"
        need(len(argv) == 8 and argv[:3] == ["/usr/bin/python3", "-I", "-B"]
             and Path(argv[3]).name == "qualify.py" and argv[4:7] == ["--request", str(request_path), "--request-sha256"]
             and output_json == str(output/"qualification.json"), "Exact passive family qualification command required")
        request = M.load(request_path, dict(bytes=request_path.lstat().st_size, sha256=argv[-1]), {})
        work = M.ordinary(request["work"])
        scratch = work.parent
        need(work.name == "work" and not any(scratch.iterdir())
             and all(not scratch.is_relative_to(other) and not other.is_relative_to(scratch)
                     for other in (output, self.source)), "Fresh dedicated qualifier scratch required")
        inventory = M.ordinary(self.plan["inventory_path"])
        exact = self.pipeline.qualification_request(self.plan, source=self.source,
                   source_map_sha256=self.plan["source_map_sha256"], output=output, work=work)
        need(request == exact, "Exact qualified request and scratch join required")
        arguments = qualifier_command(source=self.source, output=output, scratch=scratch, inventory=inventory,
                                      image=self.plan["image"], nonce=self.plan["nonce"], request_sha256=argv[-1])
        result = self.docker(*arguments, seconds=timeout)
        observed = self.retired(result, result.args)
        need(not result.stderr and 0 < len(result.stdout) <= 1024**2,
             "Complete bounded passive qualifier stdout required")
        qualified = M.decode(result.stdout)
        need(C.encoded(qualified) == result.stdout, "Canonical separate qualifier result required")
        self.absence["qualifier"] = [self.require_no_containers() for _ in range(2)]
        write_fresh(output_json, result.stdout)
        self.executions.append(observed)
        return dict(exit=0, natural=True, reaped=True, output_complete=True,
                    result=qualified, result_pin=observed["stdout"])

    def lifecycle(self, **request):
        need(self.compared and len(self.executions) == 4 and self.lifecycle_credential is not None,
             "Current qualified pair and admitted lifecycle credential required")
        return self.supervisor.lifecycle(credential=self.lifecycle_credential, **request)


def run_first_pair(*, trusted_pipeline, owner_commands, supervisor, source, source_map_sha256,
                   output, image, inventory, cache, nonce, work, failure_output, socket, binding, binding_sha256,
                   pair_only=False, lifecycle_credential=None):
    pipeline = trusted_pipeline
    for key, expected in (("QT612_FAMILY_SOURCE_ROOT", str(source)),
                          ("QT612_FAMILY_SOURCE_MAP_SHA256", source_map_sha256),
                          ("QT612_FAMILY_BINDING_PATH", str(binding)),
                          ("QT612_FAMILY_BINDING_SHA256", binding_sha256)):
        need(os.environ.get(key) == expected, "Exact separately bound family actor environment")
    plan = pipeline.stage_commands(source=source, source_map_sha256=source_map_sha256, component=COMPONENT,
                                   output=output, image=image, inventory=inventory, cache=cache, nonce=nonce)
    need(type(pair_only) is bool and pair_only == (lifecycle_credential is None), "Explicit hosted stage mode and credential")
    owned = FirstPairExecutor(pipeline, plan, owner_commands, supervisor, socket=socket,
                              source=source, binding=binding, binding_sha256=binding_sha256,
                              lifecycle_credential=lifecycle_credential)
    result = pipeline.run_stage(plan, owned, source=source, source_map_sha256=source_map_sha256,
                               output=output, work=work, failure_output=failure_output, pair_only=pair_only)
    witness = dict(kind="QT612_HOSTED_OWNED_PAIR_WITNESS_V1", mode="pair-only" if pair_only else "signed-lifecycle",
        source_map_sha256=source_map_sha256, image=image, inventory_pin=plan["inventory_pin"],
        component=COMPONENT, nonce=nonce, stage_binding_sha256=binding_sha256,
        dispatch={k:owned.binding[k] for k in ("source", "ref", "run", "job", "attempt")},
        commands=owned.executions, absence=owned.absence, qualification=pipeline.C.pin(pipeline.C.encoded(result["qualification"])))
    write_fresh(Path(output)/"owned-pair.json", pipeline.C.encoded(witness))
    return result


if __name__ == "__main__":
    raise SystemExit(build_child())
