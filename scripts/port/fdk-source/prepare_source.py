#!/usr/bin/env python3
"""Prepare a deterministic codec source packet, excluding non-source rights gaps."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

HERE=Path(__file__).resolve().parent
SOURCE=Path('/tmp/cachy-fdk-source-makepkg.tar')
SOURCE_SHA='bb97dce7e1492fe9c1373896e3bcae221ad5f2b76f95b5ee568b90499461212e'
OUTPUT=Path('/tmp/cachy-fdk-redistributable-source-3.0.0.tar.gz')
EXCLUDE={'cpp/documentation/aacDecoder.pdf','cpp/documentation/aacEncoder.pdf','rust/bitstreams/input.rawpkts'}


def main():
    assert hashlib.sha256(SOURCE.read_bytes()).hexdigest()==SOURCE_SHA
    assert not OUTPUT.exists()
    included=[];excluded=[]
    with OUTPUT.open('wb') as f, gzip.GzipFile(filename='',mode='wb',fileobj=f,mtime=0) as gz, tarfile.open(fileobj=gz,mode='w') as out, tarfile.open(SOURCE) as archive:
        for m in archive:
            assert not m.name.startswith('/') and '..' not in Path(m.name).parts
            assert m.isfile() or m.isdir()
            if m.name in EXCLUDE:
                data=archive.extractfile(m).read();excluded.append({'path':m.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()});continue
            name=m.name;m.name='fdk-aac-3.0.0/'+m.name
            data=archive.extractfile(m).read() if m.isfile() else None
            if data is not None:included.append({'path':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
            out.addfile(m,io.BytesIO(data) if data is not None else None)
        license_data=(HERE/'Apache-2.0.txt').read_bytes()
        notice=tarfile.TarInfo('fdk-aac-3.0.0/Apache-2.0.txt');notice.size=len(license_data);notice.mode=0o644
        out.addfile(notice,io.BytesIO(license_data))
    result={'schema_version':1,'scope':'complete selected codec source packet; not a publication/legal approval',
        'source_commit':'a68a51aa45d86a43c7b228e3d45624af09dcdd8d','upstream_canonical_source_sha256':SOURCE_SHA,
        'prepared_source_sha256':hashlib.sha256(OUTPUT.read_bytes()).hexdigest(),'prepared_source_bytes':OUTPUT.stat().st_size,
        'prepare_script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'included_files':included,
        'excluded_non_source_assets':excluded,'codec_and_build_source_modifications':[],
        'added_source_license_text':{'path':'Apache-2.0.txt','sha256':hashlib.sha256(license_data).hexdigest()},
        'publication':'NOT RUN','native_build':'NOT RUN'}
    (HERE/'prepared-source-manifest.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(result['prepared_source_sha256'],result['prepared_source_bytes'],len(included))


if __name__=='__main__':main()
