# SPDX-License-Identifier: MIT
"""Finite verity v1 SHA256 layout, source-derived from pinned Linux primary text."""
import hashlib,struct
BLOCK=4096;COUNT=2;CORRUPT_OFFSET=4096+37
SALT=bytes.fromhex('00112233445566778899aabbccddeeff')

def data():return bytes((i*29+(i//BLOCK)*71+(i//256)*3+17)&255 for i in range(BLOCK*COUNT))
def assets():
 good=data();bad=bytearray(good);bad[CORRUPT_OFFSET]^=1;leaves=b''.join(hashlib.sha256(SALT+good[i:i+BLOCK]).digest()for i in range(0,len(good),BLOCK));tree=leaves+bytes(BLOCK-len(leaves));return {'data.raw':good,'hash.raw':tree,'corrupt.raw':bytes(bad)}
ROOT=hashlib.sha256(SALT+assets()['hash.raw']).hexdigest()
PHASE={'create':3,'load':9,'resume':6,'table':12,'info':12,'remove':4,'gone':7}
FLAGS={'create':9,'load':1,'resume':1,'table':17,'info':1,'remove':0,'gone':0}

def parameters(data_device,hash_device):return f'1 {data_device} {hash_device} 4096 4096 2 0 sha256 {ROOT} {SALT.hex()}'
def name(role,nonce):return 'gv-'+role+'-'+nonce

def request(role,phase,nonce,paths):
 size=1024 if phase in('load','table','info')else 312;b=bytearray(size);struct.pack_into('<6Ii3IQ',b,0,4,50,0,size,312,int(phase=='load'),0,FLAGS[phase],0,0,(0 if role=='good'else 1)if phase=='create'else 0);label=name(role,nonce).encode();b[48:48+len(label)]=label
 if phase=='load':
  struct.pack_into('<QQiI16s',b,312,0,16,0,0,b'verity');text=parameters(paths[role],paths['hash']).encode();b[352:352+len(text)]=text
 return bytes(b)
def header():
 leaves=assets()['hash.raw'][:64];return ('/* SPDX-License-Identifier: MIT; generated solely by layout.py */\n#define ROOT_HEX "'+ROOT+'"\n#define SALT_HEX "'+SALT.hex()+'"\nstatic const unsigned char expected_hash[4096]={'+','.join('0x%02x'%x for x in leaves)+'};\n').encode()
def dev(encoded):return ((encoded>>8)&0xfff,(encoded&255)|((encoded>>12)&0xfff00))
def devname(encoded):return '%d:%d'%dev(encoded)
