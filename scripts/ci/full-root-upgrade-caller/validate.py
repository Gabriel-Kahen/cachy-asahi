#!/usr/bin/env python3
"""Check the proposed canonical closure in an owned tree; no native actors."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('code', 'driver', 'output'): parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    config = json.loads((here / 'upgrade-config.json').read_text())
    assert not args.output.exists()
    args.output.mkdir(mode=0o700)
    for name, pin in config['code_pins'].items():
        source = args.driver / Path(name).name if name.startswith('scripts/ci/full-root-upgrade/') else args.code / name
        data = source.read_bytes(); assert hashlib.sha256(data).hexdigest() == pin, name
        target = args.output / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
    marker = args.output / 'manifests/packages.toml'; marker.parent.mkdir()
    shutil.copyfile(args.code / 'manifests/packages.toml', marker)
    caller = args.output / 'scripts/ci/full-root-upgrade-caller'; caller.mkdir()
    for source in here.iterdir():
        if source.is_file() and source.suffix in ('.py', '.json', '.yml'):
            shutil.copyfile(source, caller / source.name)
    for path in args.output.rglob('*.py'): ast.parse(path.read_bytes(), filename=str(path))
    result = subprocess.run([sys.executable, '-B', '-m', 'unittest', 'discover', '-s', str(caller), '-p', 'test_*.py'],
                            capture_output=True, text=True)
    (here / 'validation.log').write_text(result.stdout + result.stderr)
    print(result.stdout + result.stderr, end='')
    assert result.returncode == 0
    lines = (caller / 'workflow.yml').read_text().splitlines(); shell_blocks = []
    for index, line in enumerate(lines):
        if line.strip() != 'run: |': continue
        indent = len(line) - len(line.lstrip()); body = []
        for child in lines[index + 1:]:
            if child.strip() and len(child) - len(child.lstrip()) <= indent: break
            body.append(child[indent + 2:])
        shell_blocks.append('\n'.join(body) + '\n')
    assert len(shell_blocks) == 11
    for body in shell_blocks:
        subprocess.run(['bash', '-n'], input=body, text=True, capture_output=True, check=True)
    selection = ast.parse((args.output / 'scripts/update/root_link_selection.py').read_text())
    declarations = {n.targets[0].id: n.value for n in selection.body
                    if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
                    and n.targets[0].id in ('CHAIN_PATHS', 'LINK_NODES')}
    constants = {'LINK_NODES': ast.literal_eval(declarations['LINK_NODES'])}
    derived = ast.parse('tuple(sorted(LINK_NODES))', mode='eval').body
    chain = declarations['CHAIN_PATHS']
    constants['CHAIN_PATHS'] = (tuple(sorted(constants['LINK_NODES']))
        if ast.dump(chain) == ast.dump(derived) else ast.literal_eval(chain))
    receipt = dict(python_tests='PASS', canonical_closure_files=len(config['code_pins']),
                   python_ast='PASS', workflow_shell_blocks=len(shell_blocks),
                   workflow_yaml='NOT VERIFIED: parser unavailable', native_trial='NOT RUN', hardware='NOT RUN',
                   selected_chain_paths=len(constants['CHAIN_PATHS']), selected_literal_links=len(constants['LINK_NODES']),
                   dispatch_ready=len(constants['CHAIN_PATHS']) == 87 and len(constants['LINK_NODES']) >= 87)
    (here / 'validation.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__': main()
