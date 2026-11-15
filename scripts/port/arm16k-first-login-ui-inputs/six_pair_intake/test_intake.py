# SPDX-License-Identifier: MIT
import importlib.util,json,subprocess,tempfile,unittest,urllib.error
from pathlib import Path
from unittest.mock import patch
import intake as I
class Controls(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
    def test_actual_six_descriptor_is_finite(self):
        d=json.loads((I.HERE/'inputs.json').read_text());self.assertEqual(len(d['pairs']),6);self.assertEqual(sum(p['archive']['bytes']for p in d['pairs']),1312620)
        self.assertTrue(all(p['arch']=='aarch64'and p['repo']=='extra'for p in d['pairs']))
        for p in d['pairs']:I.official(p['url']);self.assertEqual(p['expected']['pkgname'],[p['name']])
    def test_foreign_redirect_and_changed_identity_refused(self):
        for url in ['http://ca.us.mirror.archlinuxarm.org/a','https://example.org/a','https://u@ca.us.mirror.archlinuxarm.org/a','https://ca.us.mirror.archlinuxarm.org/a?q=1']:
            with self.assertRaises(ValueError):I.official(url)
        redirect=I.Redirect();request=I.urllib.request.Request('https://ca.us.mirror.archlinuxarm.org/exact')
        with self.assertRaises(ValueError):redirect.redirect_request(request,None,302,'',{},'https://mirror.archlinuxarm.org/newer')
    def test_fourth_redirect_refused(self):
        r=I.Redirect();r.redirects=[{}, {}, {}]
        with self.assertRaises(ValueError):r.redirect_request(I.urllib.request.Request('https://ca.us.mirror.archlinuxarm.org/a'),None,302,'',{},'https://mirror.archlinuxarm.org/a')
    def test_changed_retained_byte_refused(self):
        p=self.root/'archive';p.write_bytes(b'wrong')
        with self.assertRaises(ValueError):I.checked(p,{'bytes':5,'sha256':'0'*64})
    def test_request_body_and_time_limits(self):
        b=I.Budget();b.body=I.CAP
        with self.assertRaises(ValueError):b.consume(1)
        b.started-=181
        with self.assertRaises(TimeoutError):b.remaining()
        b=I.Budget();b.gets=12
        with self.assertRaises(ValueError):I.fetch('https://ca.us.mirror.archlinuxarm.org/a',{'bytes':1,'sha256':'0'*64},self.root/'x',b,{})
    def test_wrong_primary_and_bad_signature_refused(self):
        good='[GNUPG:] VALIDSIG '+I.SIGNER+' 2026-11-15 1794700000 0 4 0 1 10 00 '+I.SIGNER+'\n'
        for status in [good.replace(I.SIGNER,'A'*40),good+'[GNUPG:] BADSIG public\n','']:
            with patch.object(I.subprocess,'run',return_value=subprocess.CompletedProcess([],0,status,'')):
                with self.assertRaises(ValueError):I.verify(self.root/'a',self.root/'sig',self.root/'key',self.root,I.Budget())
    def test_valid_signature_is_not_freshness_or_runtime_acceptance(self):
        status='[GNUPG:] VALIDSIG '+I.SIGNER+' 2026-11-15 1794700000 0 4 0 1 10 00 '+I.SIGNER+'\n'
        with patch.object(I.subprocess,'run',return_value=subprocess.CompletedProcess([],0,status,''))as call:
            result=I.verify(self.root/'a',self.root/'sig',self.root/'key',self.root,I.Budget());self.assertIn('freshness/trust acceptance HOLD',result['scope']);self.assertEqual(call.call_args.args[0][0],'/usr/bin/gpgv');self.assertNotIn('--import',call.call_args.args[0])
if __name__=='__main__':unittest.main()
