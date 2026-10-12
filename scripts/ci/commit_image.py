#!/usr/bin/env python3
"""Commit one owned handoff through the pinned, local Docker API.

Moby v28.0.4 daemon/commit.go merges empty command arrays from the container.
A single empty Entrypoint prevents that merge; daemon/create.go resets it on
future container creation. The caller must independently verify final config.
https://github.com/moby/moby/blob/v28.0.4/daemon/commit.go
https://github.com/moby/moby/blob/v28.0.4/daemon/create.go
"""
import copy
import http.client
import json
import os
import re
import socket
import stat
import subprocess
import tempfile
from urllib.parse import quote, urlencode

API_VERSION = '1.48'
LIMIT = 1024**2
TIMEOUT = 120
RECOVERY_REPO = 'cachy-asahi-private-installed'
SOCKETS = {'unix:///var/run/docker.sock': '/var/run/docker.sock',
           'unix:///run/docker.sock': '/run/docker.sock'}
FIELDS = ('User', 'Env', 'Entrypoint', 'Cmd', 'WorkingDir', 'Labels', 'Volumes',
          'ExposedPorts', 'StopSignal', 'Shell', 'Healthcheck', 'ArgsEscaped')


class CommitError(ValueError):
    """A bounded error whose message never contains config or daemon output."""


def require(condition, message):
    if not condition:
        raise CommitError(message)


def strict_json(data):
    def unique(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'duplicate JSON field refused')
            result[key] = value
        return result
    def invalid(value):
        raise CommitError('nonfinite JSON refused')
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=unique, parse_constant=invalid)
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise CommitError('invalid bounded JSON') from None


def string(value):
    return isinstance(value, str) and '\0' not in value


def array(value):
    return value is None or isinstance(value, list) and all(string(item) for item in value)


def validate_config(config):
    require(isinstance(config, dict) and 'HostConfig' not in config, 'image config object without HostConfig required')
    for key in ('User', 'WorkingDir', 'StopSignal'):
        require(config.get(key) is None or string(config[key]), 'invalid image string field')
    for key in ('Env', 'Entrypoint', 'Cmd', 'Shell'):
        require(array(config.get(key)), 'invalid image array field')
    require(config.get('ArgsEscaped') is None or type(config['ArgsEscaped']) is bool, 'invalid image boolean field')
    labels = config.get('Labels')
    require(labels is None or isinstance(labels, dict) and all(string(k) and string(v) for k, v in labels.items()), 'invalid image labels')
    for key in ('Volumes', 'ExposedPorts'):
        values = config.get(key)
        require(values is None or isinstance(values, dict) and all(string(k) and v == {} for k, v in values.items()), 'invalid image set field')
    health = config.get('Healthcheck')
    if health is not None:
        require(isinstance(health, dict) and set(health) <= {'Test', 'Interval', 'Timeout', 'StartPeriod', 'StartInterval', 'Retries'}, 'invalid image healthcheck fields')
        require(array(health.get('Test')), 'invalid image healthcheck command')
        require(all(type(v) is int and v >= 0 for k, v in health.items() if k != 'Test'), 'invalid image healthcheck duration')


def commit_config(base):
    """Project portable metadata, retaining full Env and nonempty command arrays."""
    validate_config(base)
    result = {key: copy.deepcopy(base.get(key)) for key in FIELDS}
    if result['Entrypoint'] in (None, [], ['']):
        result['Entrypoint'] = ['']
        if result['Cmd'] is None:
            result['Cmd'] = []
    try:
        encoded = json.dumps(result, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode('utf-8')
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise CommitError('invalid image config encoding') from None
    require(len(encoded) <= LIMIT, 'commit request exceeds bound')
    return result


def local_endpoint():
    require(not any(key.startswith('DOCKER_') for key in os.environ), 'Docker environment overrides refused')
    try:
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as diagnostic:
            result = subprocess.run(['docker', 'context', 'inspect'], stdin=subprocess.DEVNULL,
                                    stdout=output, stderr=diagnostic, timeout=30)
            require(result.returncode == 0, 'Docker context query failed')
            output.seek(0); data = output.read(LIMIT + 1)
            require(len(data) <= LIMIT, 'Docker context exceeds bound')
        context = strict_json(data)
        require(isinstance(context, list) and len(context) == 1 and isinstance(context[0], dict), 'one Docker context required')
        endpoint = context[0]['Endpoints']['docker']['Host']
        require(endpoint in SOCKETS, 'rootful local Docker socket required')
        path = SOCKETS[endpoint]
        entry = os.lstat(path)
        require(stat.S_ISSOCK(entry.st_mode) and entry.st_uid == 0, 'root-owned Docker socket required')
        return path
    except (OSError, subprocess.SubprocessError, KeyError, TypeError):
        raise CommitError('local Docker context unavailable') from None


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        require(path in SOCKETS.values(), 'local Docker socket required')
        super().__init__('localhost', timeout=TIMEOUT)
        self.path = path

    def connect(self):
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            channel.settimeout(TIMEOUT)
            channel.connect(self.path)
        except BaseException as error:
            try:
                channel.close()
            except BaseException:
                pass
            if isinstance(error, OSError):
                raise CommitError('local Docker connection failed') from None
            raise
        self.sock = channel


def recovery_tag(container):
    """Derive the single private recovery tag from an owned handoff nonce."""
    require(isinstance(container, str) and re.fullmatch(r'cachy-asahi-handoff-[0-9a-f]{32}', container), 'owned handoff container required')
    return RECOVERY_REPO + ':' + container.rsplit('-', 1)[1]


def response_data(response):
    require((response.getheader('Content-Type') or '').split(';')[0].strip().lower() == 'application/json', 'Docker response must be JSON')
    length = response.getheader('Content-Length')
    if length is not None:
        require(isinstance(length, str) and len(length) <= 20 and length.isascii() and length.isdecimal() and int(length) <= LIMIT, 'Docker response length refused')
    data = response.read(LIMIT + 1)
    require(len(data) <= LIMIT and (length is None or len(data) == int(length)), 'Docker response exceeds bound or is incomplete')
    return strict_json(data)


def commit_image(container, config, on_submit=None):
    """Precheck a private tag, register ownership, then submit the owned commit.

    on_submit(tag) runs only after the tag's 404 precheck, before POST. Its caller
    must retain ownership through uncertain replies and clean up the tag and ID.
    The GET and POST are separate operations; this does not provide an atomic
    reservation against another writer using the same freshly generated nonce.
    """
    tag = recovery_tag(container)
    require(on_submit is None or callable(on_submit), 'submission callback must be callable')
    payload = commit_config(config)
    body = json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode('utf-8')
    connection = UnixHTTPConnection(local_endpoint())
    try:
        connection.request('GET', '/v' + API_VERSION + '/images/' + quote(tag, safe='') + '/json', headers={'Accept': 'application/json'})
        before = connection.getresponse()
        require(before.status == 404, 'private recovery tag precheck refused')
        missing = response_data(before)
        require(isinstance(missing, dict) and set(missing) == {'message'} and string(missing['message']), 'invalid recovery tag absence response')
        if on_submit is not None:
            on_submit(tag)
        path = '/v' + API_VERSION + '/commit?' + urlencode({'container': container, 'pause': 'true',
                                                          'repo': RECOVERY_REPO, 'tag': container.rsplit('-', 1)[1]})
        connection.request('POST', path, body=body, headers={'Content-Type': 'application/json', 'Content-Length': str(len(body))})
        response = connection.getresponse()
        require(response.status == 201, 'Docker commit returned unexpected status')
        result = response_data(response)
        require(isinstance(result, dict) and set(result) == {'Id'} and isinstance(result['Id'], str) and
                re.fullmatch(r'sha256:[0-9a-f]{64}', result['Id']), 'immutable Docker commit identity required')
        return result['Id']
    except (OSError, http.client.HTTPException, UnicodeError):
        raise CommitError('Docker commit transport failed') from None
    finally:
        try:
            connection.close()
        except OSError:
            raise CommitError('Docker commit connection cleanup failed') from None
