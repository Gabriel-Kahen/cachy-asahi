#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Summarize a verified materialized source context and its held builder state."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tarfile


def consumer_helper():
    # Trusted installed code only; context Python and PKGBUILD remain DATA.
    path = Path(__file__).resolve().parents[1] / 'build/mirror_consumer.py'
    spec = importlib.util.spec_from_file_location('context_info_trusted_consumer', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def summarize(context, selection_sha256, deps=None, consumer_module=None):
    consumer = consumer_module if consumer_module is not None else consumer_helper()
    deps = consumer.dependencies() if deps is None else deps
    verified = consumer.verify_context(context, selection_sha256, deps)
    mirror, source = deps['mirror'], deps['shared'][0]
    context = Path(context).absolute()
    # Bind the bytes used for this view after verification, using the same safe
    # descriptor-relative readers and caller selection pin as the consumer.
    raw = source.local_read(context, 'selection.json', source.MAX_JSON)
    source.need(mirror.digest(raw) == source.sha(selection_sha256), 'summary selection checksum mismatch')
    selection = source.decode(raw)
    source.need(verified['selection_sha256'] == selection_sha256 and verified['package'] == selection['package'],
                'summary selected package differs from verification')
    ref = selection['files']['builder-request.json']
    request_raw = source.local_read(context, 'builder-request.json', mirror.MAX_OBJECT)
    source.need((len(request_raw), mirror.digest(request_raw)) == (ref['bytes'], ref['sha256']),
                'summary builder request checksum mismatch')
    request = source.decode(request_raw)
    source.need(request['input_identity'] == selection['package'] and request['recipe_sha256'] == selection['recipe_sha256']
        and request['srcinfo_sha256'] == selection['srcinfo_sha256']
        and request['status'] == 'HELD_ACTUAL_SELECTORS_NULL'
        and all(value is None for value in request['actual_selectors'].values()),
        'summary builder state differs from verified held inputs')

    def row(name):
        return dict(path=name, **selection['files'][name])

    recipe_inputs = []
    for name, checksum in sorted(selection['recipe_inputs'].items()):
        item = row('recipe/' + name)
        source.need(item['sha256'] == checksum, 'summary recipe input pin differs')
        item['path'] = name
        recipe_inputs.append(item)
    material = [row(name) for name in sorted(selection['files']) if name.startswith('source-material/')]
    notices = [row(name) for name in sorted(selection['notice_paths'])]
    return dict(schema_version=1, purpose='mirror-builder-context-summary',
        status='VERIFIED_MIRROR_BUILDER_CONTEXT_SUMMARY', selection_sha256=selection_sha256,
        package=selection['package'], mirror_sha256=selection['mirror_sha256'],
        release_sha256=selection['release_sha256'], profile=selection['profile'],
        recipe_sha256=selection['recipe_sha256'], srcinfo_sha256=selection['srcinfo_sha256'],
        source_map_sha256=selection['source_map_sha256'], buildinfo_sha256=selection['buildinfo_sha256'],
        recipe_inputs=recipe_inputs, source_material=material, notices=notices,
        file_counts=dict(recipe_inputs=len(recipe_inputs), source_material=len(material),
                         context_files=len(selection['files'])+1),
        builder=dict(status=request['status'], actual_selectors=request['actual_selectors'],
            required_inputs=sorted(request['actual_selectors']), execution_allowed=False,
            build_tool_sha256=request['build_tool_sha256'], entry_script_sha256=request['entry_script_sha256'],
            actual_archive_sha256=request['actual_archive_sha256'], actual_archive_bytes=request['actual_archive_bytes'],
            actual_buildinfo_sha256=request['actual_buildinfo_sha256']),
        legal_acceptance=False, corresponding_source_completeness='NOT_ASSERTED',
        native_build='NOT_RUN', installation='NOT_RUN', hardware='NOT_RUN', release='NOT_ADMITTED')


class SingleValue(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        if hasattr(namespace, self.dest):
            parser.error('repeated option refused: ' + option_string)
        setattr(namespace, self.dest, value)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest='command', required=True)
    show = commands.add_parser('show', allow_abbrev=False)
    show.add_argument('--context', required=True, action=SingleValue, default=argparse.SUPPRESS)
    show.add_argument('--selection-sha256', required=True, action=SingleValue, default=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        result = summarize(Path(args.context), args.selection_sha256)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, tarfile.TarError, EOFError, RecursionError) as error:
        print(json.dumps(dict(status='REFUSED', reason=str(error)), sort_keys=True))
        return 1


if __name__ == '__main__':
    sys.dont_write_bytecode = True
    raise SystemExit(main())
