#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Collector integration using isolated local Git fixtures; no network/products."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).absolute().parent
README = 'packages/tools/cachy-asahi-release-tools-v2/README.md'
NOTICE = 'packages/tools/cachy-asahi-release-tools-v2/NOTICE'
GIT_OPTIONS = ['-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false',
               '-c', 'tag.gpgsign=false', '-c', 'protocol.allow=never',
               '-c', 'protocol.file.allow=always']


class CollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='collector-',
            dir=os.environ.get('COLLECTOR_TEST_TMPDIR', HERE))
        cls.base = Path(cls.temporary.name)
        cls.git_binary = shutil.which('git')
        if cls.git_binary is None:
            raise AssertionError('actual local Git is required; no skip')
        cls.template = cls.base / 'empty-template'; cls.template.mkdir()
        cls.ledger = Path(os.environ.get('COLLECTOR_GIT_LOG', cls.base / 'git-log.jsonl'))
        clean = {key:value for key,value in os.environ.items()
                 if not key.startswith('GIT_') and key not in ('BASH_ENV','ENV','CDPATH','SHELLOPTS','BASHOPTS')}
        cls.env = dict(clean, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
            GIT_CONFIG_SYSTEM='/dev/null', GIT_TEMPLATE_DIR=str(cls.template),
            GIT_ALLOW_PROTOCOL='file', GIT_TERMINAL_PROMPT='0', GIT_NO_REPLACE_OBJECTS='1',
            GIT_AUTHOR_NAME='Collector fixture', GIT_AUTHOR_EMAIL='collector@example.invalid',
            GIT_COMMITTER_NAME='Collector fixture', GIT_COMMITTER_EMAIL='collector@example.invalid',
            GIT_AUTHOR_DATE='2001-01-01T00:00:00+00:00',
            GIT_COMMITTER_DATE='2001-01-01T00:00:00+00:00', LC_ALL='C')
        cls.shim_bin = cls.base / 'shim-bin'; cls.shim_bin.mkdir()
        shim = cls.shim_bin / 'git'
        shim.write_text('''#!/usr/bin/env python3
import json,os,sys
with open(os.environ['COLLECTOR_GIT_LOG'],'a') as f:
 f.write(json.dumps(dict(caller='collector',cwd=os.getcwd(),argv=sys.argv[1:]),sort_keys=True)+'\\n')
if os.environ.get('COLLECTOR_DIFF_FAILURE')=='partial' and 'diff' in sys.argv[1:]:
 sys.stdout.buffer.write(b'M\\0packages/tools/cachy-asahi-release-tools-v2/README.md\\0')
 sys.stdout.buffer.flush()
 raise SystemExit(7)
options=['-c','core.hooksPath=/dev/null','-c','commit.gpgsign=false','-c','tag.gpgsign=false','-c','protocol.allow=never','-c','protocol.file.allow=always']
if os.environ.get('COLLECTOR_FETCH_FAILURE')=='after-fetch' and 'fetch' in sys.argv[1:]:
 import subprocess
 subprocess.run([os.environ['COLLECTOR_REAL_GIT'],*options,*sys.argv[1:]],check=True)
 raise SystemExit(7)
os.execv(os.environ['COLLECTOR_REAL_GIT'],[os.environ['COLLECTOR_REAL_GIT'],*options,*sys.argv[1:]])
''')
        shim.chmod(0o755)

    @classmethod
    def tearDownClass(cls):
        rows=[json.loads(line)for line in cls.ledger.read_text().splitlines()
              if str(cls.base) in line]
        assert rows and all(Path(row['cwd']).absolute().is_relative_to(cls.base)for row in rows)
        assert all(not any(arg in ('clone','push','pull','remote','ls-remote','merge-base')for arg in row['argv'])
                   for row in rows if row['caller']=='collector'), 'collector attempted acquisition'
        cls.temporary.cleanup()

    def setUp(self):
        self.case = self.base / self._testMethodName; self.case.mkdir()

    def git(self, repo, *args, check=True, data=None):
        self.assertTrue(repo.absolute().is_relative_to(self.base))
        with self.ledger.open('a') as output:
            output.write(json.dumps(dict(caller='fixture', cwd=str(repo),
                                        argv=[*GIT_OPTIONS, *args]), sort_keys=True)+'\n')
        result = subprocess.run([self.git_binary, *GIT_OPTIONS, *args], cwd=repo,
            env=self.env, input=data, stdin=subprocess.DEVNULL if data is None else None,
            capture_output=True, timeout=30)
        if check:
            self.assertEqual(result.returncode, 0, (args, result.stdout, result.stderr))
        return result

    def configure(self, repo):
        for key, value in (('user.name','Collector fixture'), ('user.email','collector@example.invalid'),
                           ('user.useConfigOnly','true'), ('core.hooksPath','/dev/null'),
                           ('commit.gpgsign','false'), ('tag.gpgsign','false'),
                           ('protocol.allow','never'), ('protocol.file.allow','always')):
            self.git(repo, 'config', '--local', key, value)

    def init(self, name='source'):
        repo=self.case/name; repo.mkdir()
        self.git(repo, 'init', '-q', '-b', 'base', '.')
        self.configure(repo)
        self.write(repo, README, 'initial\n'); self.commit(repo,'initial')
        return repo

    def write(self, repo, path, text):
        target=repo/path; target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text)

    def commit(self, repo, message):
        self.git(repo,'add','--','.')
        self.git(repo,'commit','-q','-m',message)
        return self.git(repo,'rev-parse','HEAD').stdout.decode().strip()

    def merge_graph(self):
        repo=self.init()
        self.git(repo,'switch','-q','-c','feature')
        self.write(repo,README,'feature\n'); head=self.commit(repo,'feature')
        self.git(repo,'switch','-q','base')
        self.write(repo,NOTICE,'base notice\n'); base=self.commit(repo,'base divergence')
        self.git(repo,'merge','--no-ff','--no-edit','-m','fixture merge','feature')
        merge=self.git(repo,'rev-parse','HEAD').stdout.decode().strip()
        return repo,base,head,merge

    def shallow(self, source, depth, *options):
        target=self.case/'checkout'
        self.git(self.case,'clone','-q','--no-hardlinks','--single-branch','--no-tags',
                 '--depth',str(depth),'--branch','base',*options,source.as_uri(),str(target))
        self.configure(target)
        self.assertTrue((target/'.git/shallow').is_file())
        return target

    def collect(self, repo, event, base, head, checkout, *, fail=None, name='run', expect_fetch=False):
        temporary=self.case/name;temporary.mkdir()
        output=temporary/'github-output'
        env=dict(self.env, PATH=str(self.shim_bin)+':'+os.environ['PATH'],
            COLLECTOR_REAL_GIT=self.git_binary,COLLECTOR_GIT_LOG=str(self.ledger),
            SELECTION_EVENT=event,SELECTION_BASE=base,SELECTION_HEAD=head,SELECTION_SHA=checkout,
            RUNNER_TEMP=str(temporary),GITHUB_OUTPUT=str(output))
        if fail == 'partial':
            env['COLLECTOR_DIFF_FAILURE'] = fail
        elif fail == 'after-fetch':
            env['COLLECTOR_FETCH_FAILURE'] = fail
        ledger_offset = self.ledger.stat().st_size
        result=subprocess.run(['bash',str(HERE/'collect.sh'),'static'],cwd=repo,env=env,
            stdin=subprocess.DEVNULL,capture_output=True,timeout=75)
        self.assertEqual(result.returncode,0,(result.stdout,result.stderr))
        with self.ledger.open('rb') as ledger:
            ledger.seek(ledger_offset)
            commands = [json.loads(line)['argv'] for line in ledger]
        fetches = [command for command in commands if command[0] == 'fetch']
        expected = [['fetch', '--quiet', '--depth=1', '--filter=blob:none',
                     '--no-tags', '--no-recurse-submodules', '--no-auto-maintenance',
                     '--no-write-fetch-head', '--refmap=', 'origin', base]]
        self.assertEqual(fetches, expected if expect_fetch else [])
        report=json.loads(result.stdout)
        values=dict(line.split('=',1)for line in output.read_text().splitlines())
        self.assertEqual(len(json.loads(values['matrix'])['include']),6 if report['mode']=='full'else report['groups']['static']['selected_rows'])
        return report,temporary

    def full(self, report):
        self.assertEqual(report['mode'],'full')
        self.assertEqual(report['groups']['static']['selected_rows'],6)
        self.assertEqual(report['groups']['static']['matrix']['include'][-2:],
            [dict(component='release-package',python='3.14',tests=13),
             dict(component='release-package-v2',python='3.14',tests=7)])


    def test_depth_two_verified_merge_uses_base_to_merge_tree(self):
        source,base,head,merge=self.merge_graph(); repo=self.shallow(source,2)
        self.assertEqual(self.git(repo,'rev-list','--count','HEAD').stdout.strip(),b'3')
        report,_=self.collect(repo,'pull_request',base,head,merge)
        self.assertEqual(report['mode'],'narrow')
        self.assertEqual(report['paths'],[README])
        self.assertEqual(report['groups']['static']['matrix']['include'],
                         [dict(component='release-package-v2',python='3.14',tests=7)])

    def test_depth_one_unavailable_parents_stays_full_without_fetch(self):
        source,base,head,merge=self.merge_graph();repo=self.shallow(source,1)
        self.assertNotEqual(self.git(repo,'cat-file','-e',base,check=False).returncode,0)
        report,_=self.collect(repo,'pull_request',base,head,merge);self.full(report)
        self.assertNotEqual(self.git(repo,'cat-file','-e',base,check=False).returncode,0)

    def test_sha_parent_order_and_nonmerge_mismatches_are_full(self):
        repo,base,head,merge=self.merge_graph()
        for number,(b,h,c) in enumerate(((base,head,head),(head,base,merge),('1'*40,head,merge))):
            self.full(self.collect(repo,'pull_request',b,h,c,name='mismatch%d'%number)[0])
        self.git(repo,'checkout','-q','--detach',head)
        self.full(self.collect(repo,'pull_request',base,head,head,name='nonmerge')[0])

    def test_multicommit_push_compares_exact_available_endpoints(self):
        repo=self.init();before=self.git(repo,'rev-parse','HEAD').stdout.decode().strip()
        self.write(repo,README,'first change\n');self.commit(repo,'first push commit')
        self.write(repo,NOTICE,'second change\n');head=self.commit(repo,'second push commit')
        report,_=self.collect(repo,'push',before,head,head)
        self.assertEqual(report['mode'],'narrow');self.assertEqual(report['paths'],sorted([README,NOTICE]))

    def push_graph(self):
        source = self.init()
        self.git(source, 'config', 'uploadpack.allowFilter', 'true')
        self.write(source, README, 'before\n')
        self.write(source, NOTICE, 'before notice\n')
        before = self.commit(source, 'before push')
        self.write(source, README, 'first\n')
        self.commit(source, 'one')
        self.write(source, NOTICE, 'second\n')
        head = self.commit(source, 'two')
        repo = self.shallow(source, 2, '--filter=blob:none')
        local_objects = self.git(repo, 'cat-file', '--batch-all-objects',
                                 '--batch-check=%(objectname)').stdout.splitlines()
        self.assertNotIn(before.encode(), local_objects)
        return source, repo, before, head

    def test_multicommit_push_fetches_only_exact_before_metadata(self):
        source, repo, before, head = self.push_graph()
        old_blob = self.git(source, 'rev-parse', f'{before}:{README}').stdout.strip()
        refs = self.git(repo, 'show-ref').stdout
        fetch_head = repo / '.git' / 'FETCH_HEAD'
        fetch_head.write_bytes(b'previous fetch state\n')
        report, _ = self.collect(repo, 'push', before, head, head, expect_fetch=True)
        self.assertEqual(report['mode'], 'narrow')
        self.assertEqual(report['paths'], sorted([README, NOTICE]))
        self.assertEqual(report['groups']['static']['selected_rows'], 1)
        self.assertEqual(self.git(repo, 'rev-list', '--count', before).stdout.strip(), b'1')
        objects = self.git(repo, 'rev-list', '--objects', '--missing=print', before).stdout.splitlines()
        self.assertIn(b'?' + old_blob, objects)
        self.assertEqual(self.git(repo, 'show-ref').stdout, refs)
        self.assertEqual(fetch_head.read_bytes(), b'previous fetch state\n')

    def test_unavailable_push_before_stays_full(self):
        _, repo, _, head = self.push_graph()
        report, _ = self.collect(repo, 'push', '1' * 40, head, head, expect_fetch=True)
        self.full(report)
        self.assertEqual(report['reason'], 'diff_unavailable_incomplete_or_truncated')

    def test_failed_push_fetch_stays_full_even_when_before_was_written(self):
        _, repo, before, head = self.push_graph()
        report, _ = self.collect(repo, 'push', before, head, head, fail='after-fetch', expect_fetch=True)
        self.full(report)
        self.assertEqual(self.git(repo, 'cat-file', '-t', before).stdout.strip(), b'commit')

    def test_sparse_add_materializes_reviewed_python_as_literal_paths(self):
        source = self.init()
        self.git(source, 'config', 'uploadpack.allowFilter', 'true')
        reviewed = 'scripts/release/compare_sboms.py'
        literal = 'scripts/release/reviewed[1]?.py'
        other = ['scripts/release/reviewed1a.py', 'scripts/unreviewed.py']
        for number, path in enumerate([reviewed, literal, *other]):
            self.write(source, path, f'value = {number}\n')
        self.commit(source, 'sparse source fixture')
        repo = self.shallow(source, 1, '--filter=blob:none', '--no-checkout')
        self.git(repo, 'sparse-checkout', 'set', '--no-cone', '--stdin', data=f'/{README}\n'.encode())
        self.git(repo, 'checkout', '--force', 'base')
        self.assertFalse((repo / reviewed).exists())
        policy = json.loads((HERE / 'dependencies.json').read_bytes())
        policy['paths'][literal] = policy['paths'][reviewed]
        policy['dependency_signatures'][literal] = policy['dependency_signatures'][reviewed]
        policy_path = self.case / 'policy.json'
        policy_path.write_text(json.dumps(policy))
        patterns = subprocess.check_output(
            [sys.executable, '-I', '-B', str(HERE / 'select.py'), '--policy', str(policy_path), '--sparse-paths'],
            timeout=10)
        self.git(repo, 'sparse-checkout', 'add', '--stdin', data=patterns)
        self.assertTrue(all((repo / path).is_file() for path in [README, reviewed, literal]))
        self.assertFalse(any((repo / path).exists() for path in other))

    def test_partial_valid_diff_with_nonzero_git_exit_is_full(self):
        repo,base,head,merge=self.merge_graph()
        report,temporary=self.collect(repo,'pull_request',base,head,merge,fail='partial')
        self.full(report)
        self.assertEqual(report['reason'],'diff_unavailable_incomplete_or_truncated')
        self.assertEqual((temporary/'component-name-status.z').read_bytes(),b'M\0'+README.encode()+b'\0')

    def test_real_oversized_git_diff_is_bounded_and_full(self):
        repo=self.init();before=self.git(repo,'rev-parse','HEAD').stdout.decode().strip()
        for index in range(4200):self.write(repo,'bulk/'+('%04d-'%index)+'x'*245,'x\n')
        head=self.commit(repo,'oversized name-status fixture')
        report,temporary=self.collect(repo,'push',before,head,head)
        self.full(report)
        self.assertEqual((temporary/'component-name-status.z').stat().st_size,1048577)
        self.assertIn(report['reason'],('diff_byte_bound','diff_unavailable_incomplete_or_truncated'))

    def test_manual_missing_or_zero_metadata_is_full(self):
        repo,base,head,merge=self.merge_graph()
        for number,(event,b,h,c) in enumerate((('workflow_dispatch',base,head,merge),
                ('pull_request','',head,merge),('push','0'*40,merge,merge),
                ('push','1'*40,'0'*40,merge),('push','1'*40,head,merge),
                ('push','1'*40,merge,head))):
            self.full(self.collect(repo,event,b,h,c,name='metadata%d'%number)[0])


if __name__=='__main__':unittest.main(verbosity=2)
