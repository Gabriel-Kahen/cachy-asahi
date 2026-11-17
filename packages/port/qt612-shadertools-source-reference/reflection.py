#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixed shader smoke outputs only; no loading, execution, or learned schema."""
import argparse,json,re,struct
from pathlib import Path
from source import ordinary,need

def no_duplicates(rows):
 d={}
 for k,v in rows:need(k not in d,'duplicate JSON key');d[k]=v
 return d

def check_reflection(d,stage):
 need(type(d)is dict and stage in('vertex','fragment'),'typed fixed smoke stage')
 def variable(key,name,kind,location):
  rows=d.get(key);need(type(rows)is list and len(rows)==1 and type(rows[0])is dict,'one fixed '+key);r=rows[0];need(r.get('name')==name and r.get('type')==kind and type(r.get('location'))is int and r['location']==location,'known shader variable '+name)
 variable('inputs','iPosition'if stage=='vertex'else'vColor','vec4',0);variable('outputs','vColor'if stage=='vertex'else'fragColor','vec4',0)
 blocks=d.get('uniformBlocks');need(type(blocks)is list and len(blocks)==1 and type(blocks[0])is dict,'one uniform block');b=blocks[0];need(b.get('blockName')=='buf'and type(b.get('binding'))is int and b['binding']==0 and type(b.get('set'))is int and b['set']==0,'known uniform binding/set');members=b.get('members');need(type(members)is list and len(members)==1 and type(members[0])is dict,'one uniform member');m=members[0];name,kind,size=('mvp','mat4',64)if stage=='vertex'else('opacity','float',4);need(m.get('name')==name and m.get('type')==kind and type(m.get('offset'))is int and m['offset']==0 and type(m.get('size'))is int and m['size']==size and type(b.get('size'))is int and b['size']==size,'known std140 member geometry')
 if stage=='vertex':need(m.get('matrixStride')==16 and not m.get('matrixRowMajor',False),'column-major matrix stride');need(not d.get('combinedImageSamplers'),'no vertex sampler')
 else:
  rows=d.get('combinedImageSamplers');need(type(rows)is list and len(rows)==1 and type(rows[0])is dict,'one fragment sampler');r=rows[0];need(r.get('name')=='uTexture'and r.get('type')=='sampler2D'and type(r.get('binding'))is int and r['binding']==1 and type(r.get('set'))is int and r['set']==0,'known sampler type/binding/set')
 return True

def check(directory):
 root=Path(directory);need(root.is_absolute()and root==root.resolve()and root!=Path('/'),'canonical smoke output directory');version=ordinary(root/'qsb-version.txt',4096).decode().strip();need(version=='qsb 6.12.0','exact own tool version')
 for stage in('vertex','fragment'):
  raw=ordinary(root/(stage+'.json'),128*1024);d=json.loads(raw,object_pairs_hook=no_duplicates);check_reflection(d,stage);spv=ordinary(root/(stage+'.spv'),1024**2);need(len(spv)>=20 and len(spv)%4==0 and struct.unpack_from('<I',spv)[0]==0x07230203,'SPIR-V header/whole-word geometry')
  for extension,marker in(('glsl','#version 150'),('hlsl','cbuffer'),('msl','metal_stdlib')):need(marker in ordinary(root/(stage+'.'+extension),1024**2).decode(),'required generated '+extension)
 return dict(status='PASS_FINITE_SHADER_COMPILE_REFLECTION_ONLY',stages=2,sources=['SPIR-V','GLSL','HLSL','MSL'],GPU_execution=None,native_acceptance=None,hardware=None)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--directory',type=Path,required=True);a=p.parse_args();print(json.dumps(check(a.directory),sort_keys=True))
