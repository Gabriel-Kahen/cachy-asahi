#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Versioned diagnostics for the unchanged, whole-pinned developer workflow."""
import hashlib
import importlib.util
import json
from pathlib import Path


_PATH = Path(__file__).with_name('developer_workflow.py')
_RAW = _PATH.read_bytes()
if hashlib.sha256(_RAW).hexdigest() != '531c124cde3fa41d46888acfc638c823196bb2f297b19ab68ab3d001b05f16ba':
    raise ValueError('reviewed original developer workflow pin differs')
_BASE = importlib.util.module_from_spec(importlib.util.spec_from_file_location('_diagnostic_workflow_v1', _PATH))
# A private module namespace keeps frozen consumers on their original v1 class.
exec(compile(_RAW, str(_PATH), 'exec'), _BASE.__dict__)


class _ObservedCore:
    """Forward custody unchanged; observe the effective cap supplied by v1."""
    def __init__(self, core):
        self.core, self.cap_seconds = core, None

    def __getattr__(self, name):
        return getattr(self.core, name)

    def supervise(self, child, **kwargs):
        self.cap_seconds = kwargs['cap']
        return self.core.supervise(child, **kwargs)


class Commands(_BASE.Commands):
    def run(self, *args, **kwargs):
        core, count = self.core, len(self.records)
        observed = _ObservedCore(core)
        self.core = observed
        try:
            return super().run(*args, **kwargs)
        except _BASE.Failure as error:
            # Prelaunch refusals already explain their cause and have no receipt.
            if len(self.records) != count + 1 or self.records[-1]['success']:
                raise
            row = self.records[-1]
            diagnostic = dict(step=row['step'], expected=row['expected'],
                              cap_seconds=observed.cap_seconds,
                              cancelled=list(self.cancelled), launch_error=row.get('launch_error'),
                              supervision=row['supervision'], log=row['log'], log_pin=row['log_pin'])
            try:
                with (self.output / row['log']).open('rb') as stream:
                    raw = stream.read(self.max_output + 1)
                if _BASE.pin(raw) != row['log_pin']:
                    raise ValueError('saved command log differs from receipt')
                tail = raw[-2048:]
                diagnostic.update(output_omitted_bytes=len(raw) - len(tail),
                                  output_tail=tail.decode('utf-8', errors='backslashreplace'))
            except (OSError, ValueError) as context_error:
                diagnostic['log_context_error'] = str(context_error)
            raise _BASE.Failure('command failed or retirement unknown: '
                                + json.dumps(diagnostic, sort_keys=True, ensure_ascii=True)) from error
        finally:
            self.core = core


# Only this privately loaded journey uses the successor command wrapper.
_BASE.Commands = Commands


def __getattr__(name):
    return getattr(_BASE, name)


if __name__ == '__main__':
    raise SystemExit(_BASE.main())
