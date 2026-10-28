#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite scheduling controls only; no product suites, Git or API calls."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).absolute().parent
spec=importlib.util.spec_from_file_location('component_selector',HERE/'select.py')
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
POLICY=s.policy_check(s.decode((HERE/'dependencies.json').read_bytes()))


def diff(*paths,status='M'):
    return ''.join(status+'\0'+path+'\0'for path in paths).encode()


class SelectionTests(unittest.TestCase):
    def choose(self,*paths,**kwargs):
        return s.select(POLICY,'pull_request',diff(*paths),complete=True,
                        signatures=POLICY['dependency_signatures'],**kwargs)

    def assert_full(self,report):
        self.assertEqual(report['mode'],'full')
        self.assertEqual(sum(g['selected_rows']for g in report['groups'].values()),66)
        for name,group in report['groups'].items():
            self.assertTrue(group['run'])
            self.assertEqual(group['matrix']['include'],POLICY['groups'][name]['rows'])

    def test_exact_baseline_coverage(self):
        self.assertEqual({n:len(g['rows'])for n,g in POLICY['groups'].items()},
                         {'static':6,'full-port':50,'parallel':10})
        static=POLICY['groups']['static']['rows']
        self.assertEqual([(r['component'],r['python'],r['tests'])for r in static],
            [('sbom-comparison','3.12',25),('sbom-comparison','3.14',25),
             ('developer-package','3.12',13),('developer-package','3.14',13),('release-package','3.14',13),('release-package-v2','3.14',7)])
        for name in ('full-port','parallel'):
            group=POLICY['groups'][name]
            for component in {r[group['key']]for r in group['rows']}:
                self.assertEqual({r['python']for r in group['rows']if r[group['key']]==component},{'3.12','3.14'})

    def test_comparison_selects_campaign_consumer_and_both_versions(self):
        report=self.choose('scripts/release/compare_sboms.py')
        self.assertEqual(report['mode'],'narrow')
        self.assertEqual({n:g['selected_rows']for n,g in report['groups'].items()},
                         {'static':3,'full-port':0,'parallel':2})
        self.assertFalse(report['groups']['full-port']['run'])
        self.assertEqual(report['groups']['full-port']['matrix']['include'],POLICY['groups']['full-port']['rows'])

    def test_desktop_reverse_imports(self):
        report=self.choose('scripts/workflows/desktop_application_runtime.py')
        components={r['component']for r in report['groups']['full-port']['matrix']['include']}
        self.assertEqual(components,{'app-inputs','app-runtime','app-window'})
        self.assertEqual(report['groups']['full-port']['selected_rows'],6)

    def test_mirror_borrowed_fixture_reverse_imports(self):
        report=self.choose('scripts/release/test_release_source_mirror.py')
        self.assertEqual({r['component']for r in report['groups']['full-port']['matrix']['include']},
                         {'source-mirror','source-mirror-update','mirror-builder'})
        self.assertEqual(report['groups']['parallel']['selected_rows'],2)

    def test_build_system_extension_and_packaging_consumers(self):
        report=self.choose('scripts/workflows/developer_build_systems.py')
        self.assertEqual({r['component']for r in report['groups']['full-port']['matrix']['include']},
                         {'build-systems','python-extension'})
        self.assertEqual(report['groups']['static']['selected_rows'],2)

    def test_every_reviewed_path_keeps_all_declared_consumers(self):
        for path,routes in POLICY['paths'].items():
            with self.subTest(path=path):
                report=self.choose(path)
                if report['mode']=='full':continue
                for name,group in POLICY['groups'].items():
                    wanted=[r for r in group['rows']if r[group['key']]in routes.get(name,[])]
                    actual=report['groups'][name]
                    self.assertEqual(actual['selected_rows'],len(wanted))
                    if wanted:self.assertEqual(actual['matrix']['include'],wanted)

    def test_campaign_hash_closure_cannot_be_dropped(self):
        for path,routes in POLICY['paths'].items():
            if path.endswith(('.py','.sh'))and any(path.startswith('scripts/'+d+'/')for d in ('build','checks','maintenance','release')):
                self.assertIn('campaign',routes.get('parallel',[]),path)

    def test_protected_core_platform_and_current_metrics_failure_remain_full(self):
        for path in ('scripts/virtual/owned_process.py','scripts/platform/filesystem_encoder.py',
            'scripts/checks/package_checks.py','scripts/benchmarks/platform_metrics.py',
            'scripts/benchmarks/benchmark.py','scripts/maintenance/campaign.py',
            'scripts/workflows/developer_workflow.py','manifests/packages.toml','packages/core/new/PKGBUILD'):
            with self.subTest(path=path):self.assert_full(self.choose(path))

    def test_workflow_selector_and_unknown_changes_are_full(self):
        for path in ('.github/workflows/static.yml','.github/workflows/native-arm-build.yml',
                     'scripts/ci/component_selection/dependencies.json','docs/unreviewed.md',
                     'scripts/release/new-helper.py','packages/tools/new-package/runtime.py'):
            self.assert_full(self.choose(path))

    def test_manual_other_events_and_unavailable_diff(self):
        raw=diff('scripts/release/compare_sboms.py')
        for event in ('workflow_dispatch','workflow_call','schedule','unknown'):
            self.assert_full(s.select(POLICY,event,raw,complete=True))
        self.assert_full(s.select(POLICY,'push',raw))
        self.assert_full(s.select(POLICY,'pull_request',raw,complete=True,truncated=True))

    def test_deletions_renames_and_inverse_are_full(self):
        path='scripts/release/compare_sboms.py'
        for status in ('D','R100','C100','T','U','X'):
            self.assert_full(s.select(POLICY,'pull_request',diff(path,status=status),complete=True))
        forward=s.select(POLICY,'push',diff(path,status='A'),complete=True,signatures=POLICY['dependency_signatures'])
        self.assertEqual(forward['mode'],'narrow')
        self.assert_full(s.select(POLICY,'push',diff(path,status='D'),complete=True))
        self.assert_full(s.select(POLICY,'push',b'R100\0old.py\0new.py\0',complete=True))

    def test_complete_push_and_pr_have_identical_scope(self):
        path='scripts/release/compare_sboms.py'
        self.assertEqual(self.choose(path),s.select(POLICY,'push',diff(path),complete=True,signatures=POLICY['dependency_signatures']))

    def test_order_union_monotonic_and_inverse_modification(self):
        left='scripts/release/compare_sboms.py';right='scripts/workflows/desktop_application_runtime.py'
        combined=self.choose(left,right)
        self.assertEqual(combined,self.choose(right,left))
        for single in (self.choose(left),self.choose(right)):
            for name,g in single['groups'].items():
                if g['run']:
                    encoded=lambda rows:{json.dumps(r,sort_keys=True)for r in rows}
                    self.assertTrue(encoded(g['matrix']['include'])<=encoded(combined['groups'][name]['matrix']['include']))
        self.assert_full(self.choose(left,'scripts/virtual/owned_process.py'))

    def test_malformed_duplicate_and_bounded_diff(self):
        for raw in (b'',b'M\0a.py',b'M\0',b'\xff\0bad\0',diff('../outside'),diff('/outside'),
                    diff('a//b'),diff('a/./b'),diff('a\\b'),diff('a\nb'),diff('x','x')):
            self.assert_full(s.select(POLICY,'pull_request',raw,complete=True))
        self.assert_full(s.select(POLICY,'pull_request',b'x'*(s.MAX_DIFF+1),complete=True))
        raw=b''.join(('M\0file%d.py\0'%n).encode()for n in range(s.MAX_PATHS+1))
        self.assert_full(s.select(POLICY,'pull_request',raw,complete=True))

    def test_dependency_signatures_refuse_new_cross_import_loader_or_path(self):
        original=b'value = 1\n'
        self.assertEqual(s.dependency_signature(original),s.dependency_signature(b'value = 2\n'))
        for changed in (b'import new_consumer\nvalue=1\n',b'open("new/input.json")\n',b'value=load_new_module()\n'):
            self.assertNotEqual(s.dependency_signature(original),s.dependency_signature(changed))
        path='scripts/release/compare_sboms.py'
        self.assert_full(s.select(POLICY,'pull_request',diff(path),complete=True))
        signatures=dict(POLICY['dependency_signatures']);signatures[path]='0'*64
        self.assert_full(s.select(POLICY,'pull_request',diff(path),complete=True,signatures=signatures))

    def test_signature_serialization_is_identical_on_supported_parsers(self):
        # Nested Call.func has optional empty fields whose ast.dump formatting
        # differs on 3.12/3.14. This shared identity catches that portability bug.
        source=b'import os\nfrom pathlib import Path\nfactory().method("input.json")\n'
        self.assertEqual(s.dependency_signature(source),
                         'c68387d10847b04ebeff1bb025750fea66e5915d9e260268754e5190827526d7')

    def test_export_and_recipe_set_changes_require_full(self):
        for path in POLICY['full_paths']:
            self.assert_full(self.choose(path))

    def test_bad_policy_never_produces_a_narrow_matrix(self):
        for modify in (lambda p:p['groups']['static']['rows'].append(p['groups']['static']['rows'][0]),
                       lambda p:p['paths'].update({'x.py':{'parallel':['invented']}}),
                       lambda p:p['dependency_signatures'].pop('scripts/release/compare_sboms.py'),
                       lambda p:p.update(schema_version=True)):
            changed=copy.deepcopy(POLICY);modify(changed)
            with self.assertRaises((ValueError,TypeError)):s.select(changed,'push',b'',complete=True)
        with self.assertRaisesRegex(ValueError,'duplicate'):s.decode(b'{"schema_version":1,"schema_version":1}')

    def test_pure_library_has_no_actor(self):
        with patch.object(socket,'socket',side_effect=AssertionError('network')),patch.object(
                socket,'getaddrinfo',side_effect=AssertionError('DNS')),patch.object(
                subprocess,'Popen',side_effect=AssertionError('child actor')):
            self.assertEqual(self.choose('scripts/release/compare_sboms.py')['mode'],'narrow')

    def test_cli_exact_outputs_missing_input_and_changed_dependency(self):
        with tempfile.TemporaryDirectory(prefix='selection-',dir=os.environ.get('SELECTION_TEST_TMPDIR',HERE))as temp:
            root=Path(temp);path='scripts/release/compare_sboms.py'
            source=root/path;source.parent.mkdir(parents=True);source.write_bytes(b'value = 1\n')
            policy=copy.deepcopy(POLICY);policy['dependency_signatures'][path]=s.dependency_signature(source.read_bytes())
            policyfile=root/'policy.json';policyfile.write_text(json.dumps(policy))
            raw=root/'diff.z';raw.write_bytes(diff(path));output=root/'outputs'
            argv=[sys.executable,'-I','-B',str(HERE/'select.py'),'--policy',str(policyfile),'--source-root',str(root),
                  '--event','pull_request','--diff',str(raw),'--group','static','--complete','--github-output',str(output)]
            def run():return subprocess.run(argv,capture_output=True,timeout=10,check=False)
            first=run();self.assertEqual(first.returncode,0,first.stderr)
            self.assertEqual(json.loads(first.stdout)['mode'],'narrow')
            values=dict(line.split('=',1)for line in output.read_text().splitlines())
            self.assertEqual(values['run'],'true');self.assertEqual(len(json.loads(values['matrix'])['include']),3)
            output.unlink();second=run();self.assertEqual(first.stdout,second.stdout)
            source.write_bytes(b'import unknown_cross_component\nvalue=1\n');output.unlink()
            self.assert_full(json.loads(run().stdout))
            raw.unlink();output.unlink();self.assert_full(json.loads(run().stdout))
            policyfile.write_text('{broken');output.unlink();bad=run()
            self.assertEqual(bad.returncode,1);self.assertFalse(output.exists());self.assertEqual(bad.stdout,b'')

    def test_workflow_failure_partial_outputs_use_complete_literal_fallback(self):
        root=HERE.parents[2]
        for name,group in (('static','static'),('full-port-workflows','full-port'),('parallel-development-tools','parallel')):
            workflow=(root/'.github/workflows'/(name+'.yml')).read_text()
            # Requiring success before using the matrix also covers a selector
            # that wrote narrow outputs and then failed, rather than only empty outputs.
            match=re.search(r"matrix: \$\{\{ fromJSON\(needs.component-selection.result == 'success' && needs.component-selection.outputs.matrix \|\| '(.*?)'\) \}\}",workflow)
            self.assertIsNotNone(match,name)
            self.assertEqual(json.loads(match.group(1)),dict(include=POLICY['groups'][group]['rows']))
            self.assertIn("needs.component-selection.result != 'success' || needs.component-selection.outputs.run != 'false'",workflow)
            self.assertIn('head -c 1048577',workflow)
            self.assertIn('git diff --no-ext-diff --no-renames --name-status -z',workflow)
            if group!='static':self.assertEqual(workflow.count("- '**' # Unknown paths"),2)
        static=(root/'.github/workflows/static.yml').read_text().split('  developer-release-components:',1)[0]
        self.assertIn('  checks:\n    needs: cache-seed\n',static)
        self.assertNotIn('component-selection',static)

    def test_dispatch_inventory_cannot_drift_from_full_matrix(self):
        root=HERE.parents[2]
        for name,group,variable in (('static','static','COMPONENT'),('full-port-workflows','full-port','COMPONENT'),
                                     ('parallel-development-tools','parallel','LANE')):
            workflow=(root/'.github/workflows'/(name+'.yml')).read_text()
            body=workflow.split('case "$'+variable+'" in',1)[1].split('esac',1)[0]
            cases=set(re.findall(r'^\s*([a-z][a-z0-9-]*)\)',body,re.M))
            metadata=POLICY['groups'][group]
            self.assertEqual(cases,{r[metadata['key']]for r in metadata['rows']},name)


class Integration299Tests(unittest.TestCase):
    """Incremental six-row integration controls; no product execution."""
    def choose(self,*paths,**kwargs):
        return s.select(POLICY,'pull_request',diff(*paths),complete=True,
                        signatures=POLICY['dependency_signatures'],**kwargs)

    def full_six(self,report):
        self.assertEqual(report['mode'],'full')
        self.assertEqual(report['groups']['static']['matrix']['include'],POLICY['groups']['static']['rows'])
        self.assertEqual(report['groups']['static']['selected_rows'],6)
        self.assertEqual(sum(g['selected_rows']for g in report['groups'].values()),66)

    def test_six_rows_preserve_v1_and_explicit_v2_python_counts(self):
        rows=POLICY['groups']['static']['rows']
        self.assertEqual(len(rows),6)
        self.assertEqual([r for r in rows if r['component']=='release-package'],
                         [dict(component='release-package',python='3.14',tests=13)])
        self.assertEqual([r for r in rows if r['component']=='release-package-v2'],
                         [dict(component='release-package-v2',python='3.14',tests=7)])
        self.assertEqual({g:len(p['rows'])for g,p in POLICY['groups'].items()},
                         {'static':6,'full-port':50,'parallel':10})

    def test_all_nineteen_versioned_files_have_conservative_routes(self):
        package=POLICY['versioned_packages']['release-package-v2']
        self.assertEqual(len(package['files']),19)
        self.assertEqual(len(set(package['files'])),19)
        for path in package['files']:
            self.assertIn('release-package-v2',POLICY['paths'][path]['static'])
            report=self.choose(path)
            if path in package['full_paths']:self.full_six(report)
            elif report['mode']=='narrow':
                self.assertEqual(report['groups']['static']['matrix']['include'],
                                 [dict(component='release-package-v2',python='3.14',tests=7)])
        self.assertEqual(len(package['runtime_origins']),7)

    def test_unknown_and_truncated_diffs_keep_both_release_rows(self):
        self.full_six(self.choose('packages/tools/cachy-asahi-release-tools-v2/unreviewed.py'))
        raw=diff('packages/tools/cachy-asahi-release-tools-v2/compare_sboms.py')
        self.full_six(s.select(POLICY,'pull_request',raw,complete=True,truncated=True))
        self.full_six(s.select(POLICY,'pull_request',raw,complete=False))

    def test_deleted_renamed_and_inverse_inputs_keep_six_rows(self):
        path='packages/tools/cachy-asahi-release-tools-v2/compare_sboms.py'
        for status in ('D','R100','T'):
            self.full_six(s.select(POLICY,'pull_request',diff(path,status=status),complete=True))
        self.full_six(s.select(POLICY,'pull_request',b'R100\0old.py\0new.py\0',complete=True))
        forward=s.select(POLICY,'push',diff(path,status='A'),complete=True,signatures=POLICY['dependency_signatures'])
        self.assertEqual(forward['groups']['static']['selected_rows'],1)
        self.full_six(s.select(POLICY,'push',diff(path,status='D'),complete=True))

    def test_canonical_comparator_keeps_campaign_and_v2_consumers(self):
        report=self.choose('scripts/release/compare_sboms.py')
        self.assertEqual(report['mode'],'narrow')
        self.assertEqual({g:r['selected_rows']for g,r in report['groups'].items()},
                         {'static':3,'full-port':0,'parallel':2})
        self.assertEqual({r['component']for r in report['groups']['static']['matrix']['include']},
                         {'sbom-comparison','release-package-v2'})
        self.assertEqual({r['lane']for r in report['groups']['parallel']['matrix']['include']},{'campaign'})

    def test_failed_selector_literal_fallback_has_all_six_rows(self):
        workflow=(HERE.parents[2]/'.github/workflows/static.yml').read_text()
        match=re.search(r"matrix: \$\{\{ fromJSON\(needs.component-selection.result == 'success' && needs.component-selection.outputs.matrix \|\| '(.*?)'\) \}\}",workflow)
        self.assertIsNotNone(match)
        self.assertEqual(json.loads(match.group(1))['include'],POLICY['groups']['static']['rows'])
        self.assertIn("needs.component-selection.result != 'success' || needs.component-selection.outputs.run != 'false'",workflow)
        self.assertIn('release-package-v2) suite=packages/tools/cachy-asahi-release-tools-v2/test_package.py ;;',workflow)
        self.assertIn('release-package) suite=packages/tools/cachy-asahi-release-tools/test_package.py ;;',workflow)

    def test_same_three_workflows_keep_trigger_and_central_guards(self):
        root=HERE.parents[2]
        for name in ('full-port-workflows','parallel-development-tools'):
            workflow=(root/'.github/workflows'/(name+'.yml')).read_text()
            self.assertEqual(workflow.count("- '**' # Unknown paths"),2)
            self.assertIn('    branches: [main]',workflow)
        static=(root/'.github/workflows/static.yml').read_text()
        prefix=static.split('  developer-release-components:',1)[0]
        self.assertIn('  checks:\n    needs: cache-seed\n',prefix)
        self.assertNotIn('component-selection',prefix)
        self.assertIn('from compression import zstd',static)

    def test_manual_and_protected_changes_select_full_six(self):
        raw=diff('packages/tools/cachy-asahi-release-tools-v2/compare_sboms.py')
        self.full_six(s.select(POLICY,'workflow_dispatch',raw,complete=True))
        for path in ('scripts/virtual/owned_process.py','scripts/release/source_delivery.py',
                     '.github/workflows/static.yml','scripts/platform/new-core.py'):
            self.full_six(self.choose(path))


if __name__=='__main__':unittest.main(verbosity=2)
