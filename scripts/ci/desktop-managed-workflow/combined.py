# SPDX-License-Identifier: MIT
"""Co-resident terminal/file-manager identity, layout and lifecycle helpers."""
import importlib.util
import json
import os
from pathlib import Path
import re
import time


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


T = load('combined_terminal_inputs', 'terminal_workflow.py')
F = load('combined_files_inputs', 'file_manager.py')
S = load('combined_terminal_session', 'terminal_session.py')
M = load('combined_managed_api', 'managed_session.py')
RECTANGLES = {'terminal': ([12, 12], [1000, 410]), 'thunar': ([12, 452], [1000, 300])}


def managed_identity(command, env):
    T.need(env.get('DBUS_SESSION_BUS_ADDRESS') == M.ADDRESS and env.get('XDG_RUNTIME_DIR') == str(M.RUNTIME),
           'capture must use the managed user endpoint')
    raw = os.environ.get('CACHY_MANAGED_MANAGER_PID','')
    T.need(re.fullmatch('[1-9][0-9]{0,9}',raw), 'capture manager PID required')
    return M.bus_probe(lambda argv:command(argv,'managed-capture-api'),int(raw))


def owned(clients, pid):
    T.need(type(clients) is list and all(type(c) is dict for c in clients), 'invalid combined clients')
    rows = [c for c in clients if c.get('pid') == pid and c.get('mapped') is True]
    T.need(len(rows) <= 1, 'ambiguous co-resident window')
    if not rows or rows[0].get('visible') is not True:return None
    row = rows[0]
    T.need(row.get('hidden') is False and row.get('xwayland') is False and
           re.fullmatch('0x[0-9a-fA-F]{1,16}', row.get('address', '')), 'native owned window address required')
    return row


def layout(command, clients, terminal_pid, thunar_pid):
    rows = dict(terminal=owned(clients, terminal_pid), thunar=owned(clients, thunar_pid))
    if any(row is None for row in rows.values()):return False
    T.need(rows['terminal'].get('class') == T.APP_ID and rows['terminal'].get('title') == T.TITLE and
           rows['thunar'].get('class') in ('Thunar','thunar','org.xfce.Thunar') and
           'Files' in rows['thunar'].get('title',''), 'layout app identity differs')
    for name,row in rows.items():
        address = 'address:' + row['address'];at,size = RECTANGLES[name]
        expressions = [f'hl.dsp.window.float({{action="set",window="{address}"}})',
            f'hl.dsp.window.resize({{x={size[0]},y={size[1]},relative=false,window="{address}"}})',
            f'hl.dsp.window.move({{x={at[0]},y={at[1]},relative=false,window="{address}"}})']
        for expression in expressions:
            T.need(command(['/usr/bin/hyprctl', 'dispatch', expression], 'layout').strip() == 'ok',
                   'combined layout dispatch failed')
    return True


def positioned(clients, terminal_pid, thunar_pid):
    for name,pid in (('terminal',terminal_pid),('thunar',thunar_pid)):
        row = owned(clients,pid)
        at,size = RECTANGLES[name]
        if row is None or row.get('at') != at or row.get('size') != size or row.get('floating') is not True:
            return False
    return True


def together(clients, terminal_pid, thunar_pid):
    terminal = T.window(clients, terminal_pid)
    thunar = F.window(clients, thunar_pid, 'Files')
    T.need(terminal is not None and thunar is not None, 'both owned apps must remain visible')
    rows = dict(terminal=terminal, thunar=thunar)
    for name,row in rows.items():
        owned(clients, row['pid'])
        at,size = RECTANGLES[name]
        T.need(row.get('floating') is True and row['at'] == at and row['size'] == size,
               'combined fixed layout differs: ' + name)
    T.need(terminal_pid != thunar_pid and terminal['address'] != thunar['address'] and
           type(terminal.get('monitor')) is int and terminal['monitor'] == thunar.get('monitor') and
           type(terminal.get('workspace')) is dict and type(terminal['workspace'].get('id')) is int and
           terminal['workspace']['id'] > 0 and terminal['workspace'] == thunar.get('workspace'),
           'co-resident workspace/monitor identity differs')
    a,b = terminal,thunar
    T.need(a['at'][1]+a['size'][1] < b['at'][1], 'co-resident windows overlap')
    return rows


class Terminal:
    def __init__(self, base, stage, nonce, logs, env, command):
        self.base,self.stage,self.nonce,self.logs,self.env,self.command = base,stage,nonce,logs,dict(env),command
        self.actor = None;self.proof = None;self.proof_sha = None
        self.workspace = base.HOME / ('terminal-' + stage + '-' + nonce)

    @property
    def pid(self):return self.actor.process.pid

    def healthy(self):
        if self.actor:self.actor.healthy()

    def start(self, healthy):
        self.workspace.mkdir(mode=0o700)
        (self.workspace/'alacritty.toml').write_text(T.ALACRITTY)
        self.actor = self.base.Logged(['/usr/bin/alacritty','--config-file',str(self.workspace/'alacritty.toml'),
            '--class',T.APP_ID,'--title',T.TITLE,'--working-directory',str(self.workspace),
            '--command','/usr/bin/python3','-I','-B',str(self.base.SHARE/'worker.py'),
            '--workspace',str(self.workspace),'--nonce',self.nonce,'--stage',self.stage],
            self.stage+'-alacritty',self.logs,self.env)
        S.base = self.base
        count = 0
        def mapped():
            nonlocal count
            count += 1
            rows = S.startup_clients(self.env,self.logs,self.stage+'-terminal-map-'+str(count))
            return T.window(rows,self.pid) if rows is not None else None
        S.wait(mapped,healthy,90,'visible managed terminal')
        T.publish(self.workspace/'start.json',dict(nonce=self.nonce,terminal_pid=self.pid))

    def result(self, healthy):
        def ready():
            path = self.workspace/'result.json'
            return json.loads(T.read(path)) if path.exists() else None
        result = S.wait(ready,healthy,180,'managed terminal editor/build/clipboard result')
        raw = T.read(self.workspace/'result.json')
        T.validate_result(result,self.stage,self.nonce,self.pid)
        T.need(T.read(self.workspace/'main.c',4096) == T.EDITED and
               T.sha(T.read(self.workspace/'probe',1024**2)) == result['executable']['sha256'],
               'managed terminal source/executable differs')
        S.worker_identity(result['worker_pid'],self.pid)
        self.proof,self.proof_sha = result,T.sha(raw)
        self.base.emit('terminal_workflow_result',stage=self.stage,proof=result,proof_sha256=self.proof_sha)

    def identity(self):return S.worker_identity(self.proof['worker_pid'],self.pid)

    def release(self, compositor):
        T.publish(self.workspace/'release.json',dict(nonce=self.nonce))
        self.actor.process.wait(timeout=15)
        T.need(self.actor.process.returncode == 0,'managed terminal did not exit cleanly')
        def gone():
            rows = json.loads(self.command(['/usr/bin/hyprctl','-j','clients','-a'],'terminal-retired'))
            return True if not any(c.get('pid') == self.pid and c.get('mapped') for c in rows) else None
        S.wait(gone,compositor.healthy,15,'managed terminal retirement')

    def close(self):
        if self.actor:
            first = None
            for cleanup in (lambda:self.base.terminate(self.actor.process),self.actor.finish):
                try:cleanup()
                except BaseException as error:
                    if first is None:first = error
            if first is not None:raise first
