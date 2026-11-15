# SPDX-License-Identifier: MIT
"""Focused source/refusal controls; these do not execute GTK, ALPM or a VM."""
import ast, hashlib, io, json, sys, tarfile, tempfile, unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import intake, audit, result

def witness():
    files={'.zshrc':'a'*64}
    props={'Id':'1','Name':'builder','User':[1000,'/user'],'Seat':['seat0','/seat'],'Active':True,'TTY':'tty1','Service':'login','Remote':False}
    return {'client':{'status':'PASS_REAL_SEAT_UI_CLIENT','uid':1000,'pid':100,'process_session':90,'tty':'/dev/tty1','removal_preserved_user_files':True,'private_X_server_and_session_bus_retired':True,'owned_GUI_process_retirement':{'passed':True,'group_census':'EMPTY_TWICE'},'gui':{'status':'PASS_REAL_INSTALLED_GTK_CONTROLS','uid':1000,'initial_inspect_read_only':True,'preview_read_only':True,'explicit_apply':True,'repeat_apply_preserved_user_edit':True,'rendering':{'display_type':'GdkX11Display','renderer_type':'GskCairoRenderer','root_image_bytes':3145728,'image_exported':False},'user_files':files}},'root':{'status':'PASS_UI_GUEST_ALPM_LIFECYCLE','baseline_inventory_restored':True,'package_owned_nondirectory_paths_absent':True,'original_PAM_policy_preserved':True,'unrelated_user_file_preserved':True,'installed':{'status':'INSTALLED_EXACT_128_TRUSTED_PACKAGES','baseline_count':164,'installed_count':292,'dependency_and_ownership_checks':True},'user_files_preserved':files,'trust':{'private_keys':False,'freshness_or_production_acceptance':False,'configuration':'LocalFileSigLevel = Required TrustedOnly'},'installation_receipt':{'stage':'installed','trusted_ALPM_completed':True,'exact_inventory':True,'dependencies':True,'ownership':True,'project_hashes':True,'filesystem_synced':True},'filesystem_sync':{'post-install':True,'post-remove':True,'terminal-pass':True},'client_session_corroboration':{'pid':100,'process_session':90,'login1':props}}}

class Controls(unittest.TestCase):
    def test_exact_closure(self):
        value=intake.descriptor(HERE/'closure.json')
        self.assertEqual(sum(r['bytes']for r in value['official']),141176555)
        self.assertEqual(len(value['official']),125)
    def test_metadata_data_only_and_link_refusal(self):
        with tempfile.TemporaryDirectory()as d:
            p=Path(d)/'data.tar'
            with tarfile.open(p,'w')as t:
                for name,data in [('.PKGINFO',b'pkgname = test\npkgver = 1-1\narch = any\n'),('.BUILDINFO',b'pkgbuild_sha256sum = '+b'a'*64+b'\n')]:
                    m=tarfile.TarInfo(name);m.size=len(data);t.addfile(m,io.BytesIO(data))
            self.assertEqual(audit.metadata(p)['.PKGINFO']['fields']['pkgname'],['test'])
            with tarfile.open(p,'w')as t:
                m=tarfile.TarInfo('.PKGINFO');m.type=tarfile.SYMTYPE;m.linkname='/etc/passwd';t.addfile(m)
            with self.assertRaises(AssertionError):audit.metadata(p)
    def test_checksum_and_symlink_refusal(self):
        with tempfile.TemporaryDirectory()as d:
            p=Path(d)/'input';p.write_bytes(b'good');intake.exact(p,4,hashlib.sha256(b'good').hexdigest())
            p.write_bytes(b'evil')
            with self.assertRaises(ValueError):intake.exact(p,4,hashlib.sha256(b'good').hexdigest())
            p.unlink();p.symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):intake.exact(p,4,'a'*64)
    def test_join_requires_actual_ui_and_independent_root(self):
        value=witness();result.accept(value)
        for where,key,new in [('gui','explicit_apply',False),('root','baseline_inventory_restored',False),('root','original_PAM_policy_preserved',False),('client','removal_preserved_user_files',False)]:
            value=witness();target=value['client']['gui'] if where=='gui'else value[where];target[key]=new
            with self.assertRaises(AssertionError):result.accept(value)
    def test_real_seat_not_generic_gui_success(self):
        for key,new in [('Active',False),('Seat',['seat1','/seat']),('User',[0,'/user']),('Remote',True),('TTY','ttyS0')]:
            value=witness();value['root']['client_session_corroboration']['login1'][key]=new
            with self.assertRaises(AssertionError):result.accept(value)
        value=witness();value['root']['client_session_corroboration']['pid']=999
        with self.assertRaises(AssertionError):result.accept(value)
    def test_real_render_and_trusted_alpm_required(self):
        value=witness();value['client']['gui']['rendering']['renderer_type']='MockRenderer'
        with self.assertRaises(AssertionError):result.accept(value)
        value=witness();value['root']['trust']['configuration']='LocalFileSigLevel = Never'
        with self.assertRaises(AssertionError):result.accept(value)
        value=witness();value['root']['trust']['private_keys']=True
        with self.assertRaises(AssertionError):result.accept(value)
    def test_frozen_source_and_narrow_actor_delta(self):
        repo=HERE.parents[2];refs=json.loads((HERE/'references.json').read_text())
        for path,pin in refs.items():intake.exact(repo/path,pin['bytes'],pin['sha256'])
        base=(HERE.parent/'systemd_tcg_seat_guest/vm_actor.py').read_text()
        expected=base.replace('(256*1024**2,256*1024**2)','(1024*1024**2,1024*1024**2)').replace("'-m','1536'","'-m','2048'")
        self.assertEqual((HERE/'vm_actor.py').read_text(),expected)
    def test_generated_assembly_is_compilable_and_keeps_login_contract(self):
        tree=ast.parse((HERE/'prepare.py').read_text())
        additions=[n.value.value for n in ast.walk(tree) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name)and t.id=='addition' for t in n.targets)]
        self.assertEqual(len(additions),1)
        original=(HERE.parent/'systemd_tcg_seat_guest/assemble.py').read_text()
        generated=original.replace("'/tmp/tcg-seat-root'","'/tmp/ui-seat-root'").replace('1536*1024**2','3072*1024**2')
        needle="k=Path('/usr/lib/modules/7.2.14-arch1-1')"
        generated=generated.replace(needle,additions[0]+needle)
        compile(generated,'proposed-offline-assembly','exec')
        self.assertIn('ui-client.py 2>/home/builder/UI_ERROR',generated)
        self.assertIn('No autologin, seat/session override, Polkit rule or PAM edits.',generated)
        self.assertIn('ui-owned-process.py',generated)

    def test_observer_preserves_keyboard_and_original_seat_checks(self):
        original=(HERE.parent/'systemd_tcg_seat_guest/observer.py').read_text();modified=(HERE/'observer.py').read_text()
        for line in original.splitlines():
            if line.strip().startswith("report.update(status='PASS_X86_REAL_SEAT_REFERENCE_ONLY'")or'time.monotonic()+210'in line:continue
            self.assertIn(line,modified)
        self.assertIn("ui_result.accept(ui);report['ui_journey']=ui",modified)
        self.assertIn('assert result.returncode == 0 and len(valid) == 1',(HERE/'intake.py').read_text())
        self.assertIn("'--dearmor'",(HERE/'intake.py').read_text())

if __name__=='__main__':unittest.main()
