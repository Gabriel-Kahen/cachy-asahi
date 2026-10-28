import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import preview as p


def meta(name, version='1-1', **kwargs):
    return {'NAME': [name], 'VERSION': [version], 'ARCH': ['aarch64'], 'LICENSE': ['MIT'],
            'URL': ['https://example.invalid/source'], 'SHA256SUM': ['0' * 64],
            'CSIZE': ['10'], 'FILENAME': [name + '.pkg.tar.xz']} | kwargs


def archive(path, records):
    with tarfile.open(path, 'w:gz') as t:
        for n, record in records.items():
            desc = {k:v for k,v in record.items() if k not in ['DEPENDS', 'PROVIDES', 'CONFLICTS']}
            deps = {k:v for k,v in record.items() if k in ['DEPENDS', 'PROVIDES', 'CONFLICTS']}
            for filename, d in [('desc', desc), ('depends', deps)]:
                text = ''.join('%' + k + '%\n' + '\n'.join(v) + '\n\n' for k,v in d.items())
                b=text.encode(); m=tarfile.TarInfo(n+'-'+record['VERSION'][0]+'/'+filename);m.size=len(b)
                t.addfile(m, io.BytesIO(b))


class InputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='cachy-port-', dir='/tmp')
        self.work = Path(self.tmp.name)
        self.packages = {'app':meta('app'), 'provider':meta('provider', PROVIDES=['virtual=2'])}
        self.proposal = {'schema':1,'scope':'GENERIC-builder-metadata-preview',
                         'roots':[{'name':'app','version':'1-1'}],
                         'provider_constraints':[{'name':'provider','version':'1-1'}],
                         'builder_lock_sha256':'0'*64, 'builder_inventory_sha256':'0'*64,
                         'snapshots':[{'name':n, 'sha256':'0'*64, 'size':1, 'signed':False, 'url':'https://ca.us.mirror.archlinuxarm.org/aarch64/'+n+'/'+n+'.db'} for n in ['core','extra']],
                         'optional_roots':[], 'baseline_editors':[], 'limitations':[]}
    def tearDown(self):
        self.tmp.cleanup()
    def test_json_duplicate_nonfinite_and_pin_refused(self):
        for body in ['{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}']:
            f=self.work/'data.json';f.write_text(body)
            with self.assertRaises(ValueError): p.load(f,p.digest(f))
        f.write_text('{}')
        with self.assertRaises(ValueError): p.load(f,'0'*64)
    def test_duplicate_missing_infinite_and_wrong_pinned_roots_refused(self):
        for roots in [[],[{'name':'missing','version':'1'}],self.proposal['roots']*2,
                      [{'name':'app','version':'2'}],self.proposal['roots']*101]:
            d=copy.deepcopy(self.proposal);d['roots']=roots
            with self.assertRaises(ValueError):p.proposal_check(d,self.packages)
        self.assertEqual(p.proposal_check(self.proposal,self.packages),['app=1-1','provider=1-1'])
    def test_architecture_and_version_relation_refused(self):
        for bad in [meta('app', ARCH=['x86_64']),meta('app', DEPENDS=['lib>']),
                    meta('app',PROVIDES=['--overwrite=*']),meta('app',VERSION=['../1'])]:
            with self.assertRaises(ValueError):p.check(bad)
        p.check(meta('app',DEPENDS=['soname.so=2-64','pkg>=2:1.0-1','pkg<3','pkg<=3']))
    def test_separate_database_dependency_provider_fields_retained(self):
        archive(self.work/'core.db',self.packages)
        records=[{'name':'core','sha256':p.digest(self.work/'core.db'),'size':(self.work/'core.db').stat().st_size}]
        got=p.databases(self.work,records)
        self.assertEqual(got['provider']['PROVIDES'],['virtual=2'])
        records[0]['sha256']='0'*64
        with self.assertRaises(ValueError):p.databases(self.work,records)
    def test_malformed_unselected_metadata_cannot_be_selected(self):
        archive(self.work/'core.db', {'app':meta('app', DEPENDS=['lib>'])})
        rows=[{'name':'core','sha256':p.digest(self.work/'core.db'),'size':(self.work/'core.db').stat().st_size}]
        got=p.databases(self.work,rows)
        self.assertEqual(got['app']['_invalid'], ['invalid version relation'])
        q=copy.deepcopy(self.proposal);q['provider_constraints']=[]
        with self.assertRaises(ValueError):p.proposal_check(q,got)
    def context(self):
        for n in ['root','db','cache','gpg','hooks']:(self.work/n).mkdir()
        (self.work/'pacman.conf').write_text('[options]\nArchitecture = aarch64\nSigLevel = Required DatabaseOptional\n')
    def test_host_or_custom_pacman_arguments_refused(self):
        self.context();good=p.command(self.work,'preview',['app=1-1']);p.guard(good,self.work,'preview',['app=1-1'])
        for bad in [good+['--refresh'], [x for x in good if x!='--print'],good+['--downloadonly'],
                    good+['--dbonly'],good+['--sysroot','/'],good+['--config','/etc/pacman.conf']]:
            with self.assertRaises(ValueError):p.guard(bad,self.work,'preview',['app=1-1'])
        with self.assertRaises(ValueError):p.guard(good,Path('/'),'preview',['app=1-1'])
        with self.assertRaises(ValueError):p.command(self.work,'install',['app'])
        (self.work/'pacman.conf').write_text('[options]\nInclude = /etc/pacman.conf\n')
        with self.assertRaises(ValueError):p.guard(good,self.work,'preview',['app=1-1'])
    def test_context_symlink_and_option_target_refused(self):
        self.context();shutil.rmtree(self.work/'db');(self.work/'db').symlink_to('/var/lib/pacman')
        with self.assertRaises(ValueError):p.guard(p.command(self.work,'preview',['app']),self.work,'preview',['app'])
        (self.work/'db').unlink();(self.work/'db').mkdir()
        with self.assertRaises(ValueError):p.guard(p.command(self.work,'preview',['--refresh']),self.work,'preview',['--refresh'])


@unittest.skipUnless(shutil.which('pacman') and shutil.which('vercmp'), 'actual pacman/libalpm required')
class NativeMetadataTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='cachy-port-', dir='/tmp');self.work=Path(self.tmp.name)
        self.dbdir=self.work/'snapshots';self.dbdir.mkdir()
    def tearDown(self):self.tmp.cleanup()
    def setup(self, records, installed):
        archive(self.dbdir/'core.db', records)
        r={'name':'core','sha256':p.digest(self.dbdir/'core.db'),'size':(self.dbdir/'core.db').stat().st_size}
        p.setup(self.work,self.dbdir,[r],installed)
    def test_actual_print_selects_explicit_versioned_provider_without_download(self):
        a=meta('app',DEPENDS=['virtual>=2']);x=meta('provider', '2-1',PROVIDES=['virtual=2']);y=meta('alternative',PROVIDES=['virtual=1'])
        self.setup({'app':a,'provider':x,'alternative':y}, {})
        result=p.run(self.work,'preview',['app=1-1','provider=2-1'])
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('provider\t2-1\tcore',result.stdout)
        self.assertNotIn('alternative\t',result.stdout)
        self.assertEqual(list((self.work/'cache').iterdir()),[])
        self.assertEqual(list((self.work/'db/local').iterdir()),[self.work/'db/local/ALPM_DB_VERSION'])
    def test_real_libalpm_version_epoch_soname_conflict_and_deptest(self):
        records={'app':meta('app',DEPENDS=['virtual>=2','lib.so=2-64','provider<2:1-1','provider>=1:9-1']),
                 'provider':meta('provider','1:10-1',PROVIDES=['virtual=2','lib.so=2-64'],CONFLICTS=['app<=1-1'])}
        self.setup({}, records)
        relationships,conflicts=p.alpm_audit(self.work,records)
        self.assertTrue(all(x['provider']=='provider' for x in relationships))
        self.assertEqual({conflicts[0]['package'],conflicts[0]['with']},{'app','provider'})
        missing=p.run(self.work,'deps',['virtual>2','lib.so=3-64'])
        self.assertEqual(missing.returncode,127)
        self.assertEqual(set(missing.stdout.splitlines()),{'virtual>2','lib.so=3-64'})
    def test_unversioned_provider_cannot_satisfy_version_requirement(self):
        records={'app':meta('app',DEPENDS=['virtual>=2']), 'provider':meta('provider',PROVIDES=['virtual'])}
        self.setup({},records)
        relations,_=p.alpm_audit(self.work,records)
        self.assertIsNone(relations[0]['provider'])


if __name__=='__main__':unittest.main()
