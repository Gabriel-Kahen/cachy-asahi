# SPDX-License-Identifier: MIT
"""MODEL_ONLY installed-tool filesystem controls; no tool or native execution."""
import copy,hashlib,importlib.util,json,os,subprocess,socket,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
SOURCE=ROOT/'pgo-source/packages/experiments/cachy-asahi-zlib-pgo-v1/pipeline.py'
spec=importlib.util.spec_from_file_location('_MODEL_ONLY_installed_tool_pipeline',SOURCE);P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)


class ModelRunner:
    def __init__(self,output):self.output=output;self.labels=[]
    def run(self,label,argv):
        self.labels.append((label,argv))
        if label=='tool-target':return b'aarch64-unknown-linux-gnu\n'
        if label.startswith('tool-path-'):
            name={'cc1':'cc1','collect2':'collect2','libgcov-a':'libgcov.a'}[label.removeprefix('tool-path-')]
            return(P.TOOL_POLICY[name]['path']+'\n').encode()
        return b'MODEL_ONLY-tool-version\n'


class OwnedToolIdentityControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='MODEL_ONLY-tool-identity-');self.addCleanup(self.temp.cleanup)
        self.work=Path(self.temp.name);self.root=self.work/'MODEL_ONLY-root';self.root.mkdir()
        result=self.work/'MODEL_ONLY-result';result.mkdir();commands=result/'commands';commands.mkdir();self.runner=ModelRunner(commands)
        self.policy=copy.deepcopy(P.TOOL_POLICY);self.overrides={};packages={}
        for role,row in self.policy.items():
            body=('MODEL_ONLY-'+role+'\n').encode();row['payload']=dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
            first=self.physical(row['hardlinks'][0]);first.parent.mkdir(parents=True,exist_ok=True);first.write_bytes(body);first.chmod(row['mode'])
            for name in row['hardlinks'][1:]:self.physical(name).parent.mkdir(parents=True,exist_ok=True);os.link(first,self.physical(name))
            for name,target in row['symlinks'].items():self.physical(name).symlink_to(target)
            package=row['package'];key=package['name']+'-'+package['version'];entry=packages.setdefault(key,dict(package=package,members=set()))
            entry['members'].update(n.removeprefix('/')for n in set(row['hardlinks'])|set(row['symlinks']))
        for key,row in packages.items():
            directory=self.physical('/var/lib/pacman/local/'+key);directory.mkdir(parents=True)
            (directory/'desc').write_text(''.join('%'+tag+'%\n'+row['package'][name]+'\n\n'for tag,name in(('NAME','name'),('VERSION','version'),('ARCH','arch'))))
            (directory/'files').write_text('%FILES%\n'+'\n'.join(sorted(row['members']))+'\n')
        self.enterContext(patch.object(P,'_TOOL_ROOT',self.root));self.enterContext(patch.object(P,'TOOL_POLICY',self.policy))
        actual_lstat=P._tool_lstat;actual_fstat=os.fstat
        def modeled(info,changes=None):
            values={'st_'+k:v for k,v in P._tool_state(info).items()};values.update(st_uid=0,st_gid=0)
            if changes:values.update(changes)
            return SimpleNamespace(**values)
        self.enterContext(patch.object(P,'_tool_lstat',side_effect=lambda n:modeled(actual_lstat(n),self.overrides.get(n))))
        self.enterContext(patch.object(P.os,'fstat',side_effect=lambda fd:modeled(actual_fstat(fd))))
        for name in('Popen','run','check_output'):self.enterContext(patch.object(subprocess,name,side_effect=AssertionError('MODEL_ONLY no process/tool execution')))
        self.enterContext(patch.object(socket,'socket',side_effect=AssertionError('MODEL_ONLY no network')))
    def physical(self,name):return self.root.joinpath(*Path(name).parts[1:])
    def read_tool(self,role='gcc'):
        row={};body=P.installed_tool(role,self.policy[role]['path'],row);return body,row
    def database(self,role,leaf):
        row=self.policy[role]['package'];return self.physical('/var/lib/pacman/local/'+row['name']+'-'+row['version']+'/'+leaf)

    def test_declared_hardlinks_and_aliases_allow_only_exact_installed_tool_rows(self):
        result=P.toolchain(self.runner);self.assertEqual(set(result['tools']),set(P.TOOL_POLICY))
        self.assertTrue(all(set(row)=={'path','resolved_path','bytes','sha256','version'}for row in result['tools'].values()))
        self.assertEqual(result['tools']['gcc']['resolved_path'],'/usr/bin/gcc')
        self.assertEqual(self.physical('/usr/bin/gcc').stat().st_nlink,3)
        self.assertEqual([label for label,_ in self.runner.labels],['tool-target',*['tool-'+n for n in P.TOOLS],'tool-path-cc1','tool-path-collect2','tool-path-libgcov-a'])
        report=json.loads((self.runner.output.parent/'tool-identity-observations.json').read_bytes())
        self.assertEqual(report['probes'][0]['status'],'PASS_ALL_TEN_INSTALLED_TOOL_IDENTITIES');self.assertEqual(len(report['probes'][0]['tools']),10)

    def test_source_profile_and_output_reader_remains_single_link_no_alias(self):
        for name in('/usr/bin/gcc','/usr/bin/cc'):
            with self.subTest(name=name),self.assertRaises(ValueError):P.read(self.physical(name))
        source=self.work/'MODEL_ONLY-source';source.write_bytes(b'source');os.link(source,self.work/'MODEL_ONLY-source-alias')
        with self.assertRaises(ValueError):P.read(source)

    def test_unknown_logical_path_and_changed_symlink_route_refuse(self):
        with self.assertRaises(ValueError):P.installed_tool('gcc','/usr/bin/cc',{})
        alias=self.physical('/usr/bin/cc');alias.unlink();alias.symlink_to('make')
        with self.assertRaisesRegex(ValueError,'symlink route'):self.read_tool()

    def test_unknown_extra_hardlink_refuses(self):
        os.link(self.physical('/usr/bin/gcc'),self.root/'MODEL_ONLY-unknown-link')
        with self.assertRaisesRegex(ValueError,'hardlink group'):self.read_tool()

    def test_writable_parent_or_nonroot_node_refuses_before_any_command(self):
        self.overrides['/usr/bin/gcc']={'st_uid':1000}
        with self.assertRaisesRegex(ValueError,'root ownership'):P.toolchain(self.runner)
        self.assertEqual(self.runner.labels,[])
        detail=json.loads((self.runner.output.parent/'tool-identity-error.json').read_bytes())
        self.assertEqual(detail['probe']['tools'][0]['role'],'gcc')
        self.assertEqual(detail['probe']['tools'][0]['nodes']['/usr/bin/gcc']['uid'],1000)
        self.assertEqual(detail['probe']['status'],'FAIL')

    def test_writable_parent_refuses(self):
        self.physical('/usr/bin').chmod(0o777)
        with self.assertRaisesRegex(ValueError,'nonwritable directory'):self.read_tool()

    def test_wrong_payload_refuses_even_with_declared_inode_group(self):
        path=self.physical('/usr/bin/gcc');body=path.read_bytes();path.write_bytes(b'X'+body[1:])
        with self.assertRaisesRegex(ValueError,'payload differs'):self.read_tool()

    def test_installed_package_version_architecture_and_membership_are_required(self):
        desc=self.database('gcc','desc');raw=desc.read_text();desc.write_text(raw.replace('aarch64','MODEL_ONLY-wrong-arch'))
        with self.assertRaisesRegex(ValueError,'name/version/architecture'):self.read_tool()
        desc.write_text(raw);files=self.database('gcc','files');files.write_text(files.read_text().replace('usr/bin/cc\n',''))
        with self.assertRaisesRegex(ValueError,'membership missing'):self.read_tool()

    def test_fd_or_path_mutation_during_read_is_refused(self):
        target=self.physical('/usr/bin/gcc');inode=target.stat().st_ino;actual_read=os.read;actual_fstat=P.os.fstat;changed=[]
        def read(fd,cap):
            raw=actual_read(fd,cap)
            if actual_fstat(fd).st_ino==inode and raw and not changed:changed.append(True);target.chmod(0o700)
            return raw
        with patch.object(P.os,'read',side_effect=read),self.assertRaisesRegex(ValueError,'changed during FD read'):self.read_tool()
        self.assertTrue(changed)



    def test_diagnostic_data_outputs_reject_aliases_and_multiple_links(self):
        output=Path(self.runner.output).parent;victim=self.work/'MODEL_ONLY-untouched';victim.write_bytes(b'unchanged')
        for filename in('tool-identity-observations.json','tool-identity-error.json'):
            for kind in('symlink','hardlink'):
                for name in('tool-identity-observations.json','tool-identity-error.json'):
                    path=output/name
                    if path.exists()or path.is_symlink():path.unlink()
                path=output/filename
                if kind=='symlink':path.symlink_to(self.work/'MODEL_ONLY-dangling')
                else:os.link(victim,path)
                with self.subTest(filename=filename,kind=kind),self.assertRaises(ValueError):
                    P._tool_identity_diagnostics(self.runner,dict(status='FAIL',tools=[]),ValueError('MODEL_ONLY'))
                self.assertEqual(victim.read_bytes(),b'unchanged');self.assertFalse((self.work/'MODEL_ONLY-dangling').exists())

if __name__=='__main__':unittest.main()
