# SPDX-License-Identifier: MIT
"""First Qt family pair callbacks for the existing private hosted owner."""

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


class FirstPairExecutor:
    """Run the exact builds and comparison using the retained 349 owner's command runner."""

    API = "ROOT_QT612_COMPLETE_FAMILY_OWNED_EXECUTOR_V1"

    def __init__(self, pipeline, plan, owner_commands, supervisor, *, socket, source, binding, binding_sha256):
        need(plan["component"] == COMPONENT and plan["serial"] is True, "Select the first serial family pair")
        self.pipeline = pipeline
        self.plan = plan
        self.commands = owner_commands
        self.supervisor = supervisor
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

    def authenticate_Root_stage_binding(self, binding):
        self.supervisor.authenticate_Root_stage_binding(binding)
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

    def docker(self, *args):
        need(self.domain_verified and private_socket(str(self.endpoint))[1] == self.socket_identity,
             "Same authenticated scoped daemon socket required")
        return self.commands([DOCKER, self.host_option, *args], 8)

    def require_no_containers(self):
        need(self.inventory_verified, "Authenticate inventory before container checks")
        need(self.docker("container", "ls", "-a", "--no-trunc", "--quiet").stdout == b"",
             "The dedicated daemon must have no containers")

    def require_absent_twice(self, name):
        expected = "cachy-qt612-family-" + self.plan["nonce"] + "-gui_server-" + str(self.attempt)
        need(self.attempt in (1, 2) and name == expected and not self.absence_confirmed,
             "Check absence of the exact completed attempt")
        for _ in range(2):
            need(self.docker("container", "ls", "-a", "--no-trunc", "--quiet",
                             "--filter", "name=^/" + name + "$").stdout == b"",
                 "Owned GUI build container remains on the daemon")
        self.absence_confirmed = True

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
        row = self.commands.rows[-1]
        need(row["argv"] == launch, "Same naturally retired command record required")
        record = row["retirement"]
        need(result.returncode == record["exit"] == 0 and record["reaped"] is True
             and record["ownership"] == "REAPED" and record["group_census"] == "EMPTY_TWICE"
             and record["output_complete"] is True and not record["signals"] and not record["timeout"]
             and record["error"] is None, "Natural complete hosted command retirement required")
        if stdout is None:
            self.attempt += 1
            self.absence_confirmed = False
        else:
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(result.stdout)
            self.compared = True
        return dict(exit=0, natural=True, reaped=True, output_complete=True)

    def qualify(self, **request):
        need(self.compared, "Strict comparison must precede the passive qualifier")
        return self.supervisor.qualify(**request)

    def lifecycle(self, **request):
        need(self.compared, "Strict comparison must precede private lifecycle")
        return self.supervisor.lifecycle(**request)


def run_first_pair(*, trusted_pipeline, owner_commands, supervisor, source, source_map_sha256,
                   output, image, inventory, cache, nonce, work, failure_output, socket, binding, binding_sha256):
    pipeline = trusted_pipeline
    for key, expected in (("QT612_FAMILY_SOURCE_ROOT", str(source)),
                          ("QT612_FAMILY_SOURCE_MAP_SHA256", source_map_sha256),
                          ("QT612_FAMILY_BINDING_PATH", str(binding)),
                          ("QT612_FAMILY_BINDING_SHA256", binding_sha256)):
        need(os.environ.get(key) == expected, "Exact separately bound family actor environment")
    plan = pipeline.stage_commands(source=source, source_map_sha256=source_map_sha256, component=COMPONENT,
                                   output=output, image=image, inventory=inventory, cache=cache, nonce=nonce)
    executor = FirstPairExecutor(pipeline, plan, owner_commands, supervisor, socket=socket,
                                 source=source, binding=binding, binding_sha256=binding_sha256)
    return pipeline.run_stage(plan, executor, source=source, source_map_sha256=source_map_sha256,
                              output=output, work=work, failure_output=failure_output)


if __name__ == "__main__":
    raise SystemExit(build_child())
