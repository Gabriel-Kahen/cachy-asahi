# SPDX-License-Identifier: MIT
"""Fixed US qcode plans. No PTY, guest execution, clipboard or callback channel."""
import hashlib
import json
import re
import time

STEPS=('launch','shell','editor-open','editor-type','editor-save','editor-quit','result','close')
VIEWS=('shell','editor','result')
FRAMES=tuple(s+'-'+v for s in ('minimal','overlay') for v in VIEWS)
STATUS='PASS_MANAGED_VIRTUAL_KEYBOARD_METADATA'


def need(ok,message):
    if not ok:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()


def expected(nonce):
    need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce),'exact keyboard nonce required')
    return {name:(prefix+nonce+'\n').encode() for name,prefix in
            (('shell.txt','shell-'),('edit.txt','editor-'),('result.txt','shell-'))} | {
            'result.txt':('shell-'+nonce+'\neditor-'+nonce+'\n').encode()}


def plan(stage,nonce,step):
    need(stage in ('minimal','overlay') and step in STEPS,'fixed keyboard stage/step required')
    expected(nonce)
    workspace='/home/desktop574/keyboard-'+stage+'-'+nonce
    text={
        'shell':"cd "+workspace+"; export PS1='keyboard> '; printf 'shell-"+nonce+"\\n' | tee shell.txt\n",
        'editor-open':'vim -u NONE -i NONE -n edit.txt\n',
        'editor-type':'ieditor-'+nonce,
        'editor-save':'\x1b:w\n',
        'editor-quit':':q\n',
        'result':'cat shell.txt edit.txt | tee result.txt\n'}
    if step=='launch':return [['meta_l','ret']]
    if step=='close':return [['meta_l','q']]
    return [qcodes(c) for c in text[step]]


def qcodes(char):
    if char in 'abcdefghijklmnopqrstuvwxyz0123456789':return [char]
    if char in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':return ['shift',char.lower()]
    plain={' ':'spc','\n':'ret','\x1b':'esc','-':'minus','=':'equal','[':'bracket_left',
           ']':'bracket_right',';':'semicolon',"'":'apostrophe','\\':'backslash',',':'comma',
           '.':'dot','/':'slash','`':'grave_accent'}
    shifted={'_':'minus','+':'equal','{':'bracket_left','}':'bracket_right',':':'semicolon',
             '"':'apostrophe','|':'backslash','<':'comma','>':'dot','?':'slash','~':'grave_accent',
             '!':'1','@':'2','#':'3','$':'4','%':'5','^':'6','&':'7','*':'8','(':'9',')':'0'}
    if char in plain:return [plain[char]]
    need(char in shifted,'unsupported keyboard character')
    return ['shift',shifted[char]]


def send(qmp,chords,*,pause=time.sleep):
    need(type(chords) is list and 1<=len(chords)<=512,'finite key plan required')
    calls=0
    for chord in chords:
        down=[]
        try:
            for key in chord:
                # Mark uncertainty before sending: an interrupted reply may follow an accepted press.
                down.append(key)
                qmp.execute('input-send-event',{'events':[dict(type='key',data=dict(down=True,key=dict(type='qcode',data=key)))]});calls+=1
            pause(.04)
        finally:
            first=None
            for key in reversed(down):
                try:qmp.execute('input-send-event',{'events':[dict(type='key',data=dict(down=False,key=dict(type='qcode',data=key)))]});calls+=1
                except BaseException as error:
                    if first is None:first=error
            if first is not None:raise first
        pause(.04)
    return calls


class Controller:
    def __init__(self):self.stage_index=0;self.index=0;self.nonces={};self.records=[]
    def handle(self,qmp,row):
        stage=('minimal','overlay')[min(self.stage_index,1)]
        need(self.stage_index<2 and row.get('stage')==stage and row.get('step')==STEPS[self.index],
             'keyboard request duplicate/out of order')
        nonce=row.get('nonce');chords=plan(stage,nonce,row['step'])
        need(self.nonces.setdefault(stage,nonce)==nonce,'keyboard phase nonce changed')
        need(row.get('plan_sha256')==sha(encoded(chords)),'keyboard request plan differs')
        if self.index==0:
            need(any(x.get('name')=='input-send-event' for x in qmp.execute('query-commands')),'QMP keyboard command absent')
            need(qmp.execute('query-status').get('status')=='running','QEMU is not running')
        count=send(qmp,chords)
        proof=dict(event='qmp_keyboard_input',stage=stage,step=row['step'],nonce=nonce,
                   plan_sha256=sha(encoded(chords)),chords=len(chords),qmp_calls=count,
                   route='input-send-event/virtio-keyboard-pci',all_keys_released=True)
        self.records.append(proof)
        self.index+=1
        if self.index==len(STEPS):self.index=0;self.stage_index+=1
        return proof
