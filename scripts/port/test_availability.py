import io
import json
from pathlib import Path
import urllib.error
import unittest
import availability as a

URL='https://ca.us.mirror.archlinuxarm.org/aarch64/extra/fixture.pkg.tar.xz'


class Response(io.BytesIO):
    def __init__(self,data=b'',status=200,length='7',url=URL):
        super().__init__(data);self.status=status;self.headers={'Content-Length':length};self.url=url;self.calls=[]
    def read(self,n=-1):
        self.calls.append(n)
        if n!=1:raise AssertionError('unbounded/body HEAD read')
        return super().read(n)


class AvailabilityTests(unittest.TestCase):
    def test_HEAD_reads_no_payload_and_reports_unconfirmed_length_honestly(self):
        r=Response(b'payload')
        got=a.probe(URL,7,lambda request,**kwargs:r)
        self.assertEqual(got['availability'],'HTTP-success-size-match')
        self.assertEqual(r.calls,[]);self.assertTrue(r.closed)
        got=a.probe(URL,7,lambda request,**kwargs:Response(length='8'))
        self.assertEqual(got['availability'],'HTTP-success-length-unconfirmed-or-mismatch')
    def test_only_unsupported_HEAD_triggers_bounded_GET(self):
        methods=[];response=Response(b'unbounded response from Range-ignorant server',status=200,length='99999999')
        def open_(request,**kwargs):
            methods.append(request.get_method())
            if len(methods)==1:raise urllib.error.HTTPError(URL,405,'unsupported',{},None)
            self.assertEqual(request.get_header('Range'),'bytes=0-0')
            return response
        got=a.probe(URL,7,open_)
        self.assertEqual(methods,['HEAD','GET']);self.assertEqual(response.calls,[1]);self.assertTrue(response.closed)
        self.assertEqual(got['body_bytes_read'],1)
        self.assertEqual(got['authentication'],'NOT RUN')
    def test_404_and_TLS_failure_not_retried_or_relaxed(self):
        for error in [urllib.error.HTTPError(URL,404,'Not Found',{},None),urllib.error.URLError('CERTIFICATE_VERIFY_FAILED')]:
            calls=[]
            def open_(request,**kwargs):calls.append(request.get_method());raise error
            got=a.probe(URL,7,open_)
            self.assertEqual(calls,['HEAD']);self.assertEqual(got['availability'],'unavailable')
            self.assertEqual(got['body_bytes_read'],0)
    def test_nonofficial_HTTP_credentials_and_redirect_rejected(self):
        for url in ['http://ca.us.mirror.archlinuxarm.org/file','https://other.invalid/file',
                    'https://secret@ca.us.mirror.archlinuxarm.org/file',URL+'?token=x']:
            with self.assertRaises(ValueError):a.probe(url,7)
        got=a.probe(URL,7,lambda request,**kwargs:Response(url='http://other.invalid/file'))
        self.assertEqual(got['availability'],'unavailable')
        self.assertEqual(got['body_bytes_read'],0)
    def test_original_finite_set_and_pins_preserved(self):
        lock=json.loads((Path(__file__).resolve().parents[2]/'docs/validation/input-snapshots/7d53775b2de6136d531a7f20059088def7bbb11ad8baef58e75cd5826e3a2b41.json').read_text())
        items=a.items(lock);self.assertEqual(len(items),501)
        self.assertEqual(items[4]['url'],items[3]['url']+'.sig')
        changed=dict(lock);changed['packages']=lock['packages'][:-1]
        with self.assertRaises(ValueError):a.items(changed)


if __name__=='__main__':unittest.main()
