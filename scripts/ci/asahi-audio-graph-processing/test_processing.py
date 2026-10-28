"""Pure numerical/projection controls. Never runs a native host or plugin."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('processing_container', HERE/'container.py')
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)
COMMON = c.s.held('container')


def processing(case, signal='noise', value=0.001):
    return dict(fixture=signal, block_frames=1024, blocks=128, inputs=case['inputs'], outputs=case['outputs'],
                samples_per_channel=131072, process_calls=128, input_immutable=True, guards=True,
                finite=True, duplicates=True, peak=[value]*case['outputs'],
                energy=[value*value*131072]*case['outputs'], bytes=case['outputs']*131072*4)


def sample(case, value=0.001):
    # Use exactly representable f32 for independent metric agreement.
    value = struct.unpack('<f', struct.pack('<f', value))[0]
    return struct.pack('<f', value) * (case['outputs']*131072), value


class Controls(unittest.TestCase):
    def setUp(self):
        self.common = patch.object(c, 'common', return_value=COMMON); self.common.start()
        self.case=c.s.cases()['j415-speakers']; self.data,self.value=sample(self.case)
        self.metrics=processing(self.case,value=self.value)
    def tearDown(self): self.common.stop()
    def refuses(self, fn, *args):
        with self.assertRaises(COMMON.Failure): fn(*args)
    def test_nonvacuous_positive_all_outputs(self):
        self.assertEqual(c.validate_samples(self.data,self.case,self.metrics),self.data)
    def test_all_graph_shapes(self):
        for case in c.s.cases().values():
            data,v=sample(case);c.validate_samples(data,case,processing(case,value=v))
    def test_silence(self):
        c.validate_samples(bytes(len(self.data)),self.case,processing(self.case,'silence',0))
    def test_noise_silent_output(self):
        data=bytearray(self.data)
        for block in range(128): data[(block*6+2)*4096:(block*6+3)*4096]=bytes(4096)
        metrics=copy.deepcopy(self.metrics);metrics['energy'][2]=0;metrics['peak'][2]=0
        self.refuses(c.validate_samples,bytes(data),self.case,metrics)
    def test_nonfinite_output(self):
        for v in (float('nan'),float('inf'),-float('inf')):
            data=struct.pack('<f',v)+self.data[4:]
            self.refuses(c.validate_samples,data,self.case,self.metrics)
    def test_length(self):
        for data in (self.data[:-4],self.data+b'0000',b''):
            self.refuses(c.validate_samples,data,self.case,self.metrics)
    def test_wrong_duplicate_one_block(self):
        data=bytearray(self.data);data[(127*6+4)*4096:(127*6+4)*4096+4]=struct.pack('<f',0.002)
        self.refuses(c.validate_samples,bytes(data),self.case,self.metrics)
    def test_metric_lie(self):
        for key in ('peak','energy'):
            row=copy.deepcopy(self.metrics);row[key][0]*=2
            self.refuses(c.validate_samples,self.data,self.case,row)
    def test_silence_nonzero(self):
        row=processing(self.case,'silence',0)
        self.refuses(c.validate_samples,self.data,self.case,row)
    def test_guard_ownership_claims(self):
        for key in ('guards','input_immutable','finite','duplicates'):
            row=copy.deepcopy(self.metrics);row[key]=False
            self.refuses(c.validate_processing,row,self.case,'positive')
    def test_schema_closed(self):
        for key in ('extra','peak'):
            row=copy.deepcopy(self.metrics)
            if key=='extra': row[key]=True
            else: row[key]=[True]*6
            self.refuses(c.validate_processing,row,self.case,'positive')
    def test_count_bool_rejected(self):
        row=copy.deepcopy(self.metrics);row['blocks']=True
        self.refuses(c.validate_processing,row,self.case,'positive')
    def test_negative_no_processing(self):
        c.validate_processing(None,self.case,'malformed')
        self.refuses(c.validate_processing,self.metrics,self.case,'malformed')
    def test_repeat_requires_bytes_equal(self):
        c.validate_sample_pairs({('j413-mic','noise',0):b'a',('j413-mic','noise',1):b'a'})
        self.refuses(c.validate_sample_pairs,{('j413-mic','noise',0):b'a',('j413-mic','noise',1):b'b'})
    def test_microphone_correspondence(self):
        for signal in ('silence','noise'):
            c.validate_sample_pairs({('j413-mic',signal,0):b'a',('j415-mic',signal,0):b'a'})
            self.refuses(c.validate_sample_pairs,{('j413-mic',signal,0):b'a',('j415-mic',signal,0):b'b'})
    def test_complete_grid_no_vacuous_success(self):
        self.refuses(c.validate_sample_pairs,{},True)
        rows={(case,signal,repeat):b'a' for case in c.s.cases() for signal in ('silence','noise') for repeat in range(2)}
        c.validate_sample_pairs(rows,True)
        rows.pop(('j413-mic','noise',1));self.refuses(c.validate_sample_pairs,rows,True)
    def test_source_pins(self):
        for name,pin in c.ADAPTER_SOURCES.items(): self.assertEqual(c.s.sha(HERE/'adapter'/name),pin)
    def test_fail_closed_public(self):
        self.refuses(c.validate_public,{})
    def test_adapter_official_identity_distinct(self):
        self.assertEqual(c.library_identity(c.ADAPTER),c.ADAPTER_IDENTITY)
        self.assertNotEqual(c.library_identity(c.OFFICIAL_ADAPTER),c.ADAPTER_IDENTITY)

if __name__=='__main__':unittest.main()
