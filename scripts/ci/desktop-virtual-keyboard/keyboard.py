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


def verify_keyboards(keyboards,board=None):
    """One typed QEMU keyboard, optionally the pinned board's power-only input."""
    need(type(keyboards) is list and 1<=len(keyboards)<=2 and all(type(k) is dict for k in keyboards),
         'bounded compositor keyboard list required')
    names=[k.get('name') for k in keyboards]
    need(names.count('qemu-virtio-keyboard')==1 and names.count('gpio-keys')<=1 and
         set(names)<={'qemu-virtio-keyboard','gpio-keys'},'unexpected or duplicate keyboard')
    need(all(k.get('layout')=='us' and k.get('capsLock') is False for k in keyboards),
         'Hyprland US virtual keyboard differs')
    if 'gpio-keys' not in names:
        need(board is None,'unjoined board input proof');return
    need(type(board) is dict and board.get('name')=='gpio-keys' and board.get('driver')=='gpio-keys' and
         type(board.get('sysfs')) is str and re.fullmatch(r'/sys/devices/platform/gpio-keys/input/input[0-9]{1,6}',board['sysfs']) and
         board.get('bus_type')==25 and board.get('of_node')=='/sys/firmware/devicetree/base/gpio-keys' and
         board.get('compatible_hex')=='6770696f2d6b65797300' and board.get('poweroff_linux_code_hex')=='00000074',
         'board power-button identity differs')
    text=board.get('key_bitmap');need(type(text) is str and re.fullmatch('[0-9a-f]{1,16}( [0-9a-f]{1,16}){0,11}',text),
                                         'bounded ARM64 input key bitmap required')
    bits=sum(int(word,16)<<(64*i) for i,word in enumerate(reversed(text.split())))
    need(bits==1<<116,'board device is not KEY_POWER-only')
    need(type(board.get('event')) is str and re.fullmatch('event[0-9]{1,6}',board['event']) and
         board.get('node')=='/dev/input/'+board['event'] and type(board.get('major')) is int and board['major']==13 and
         type(board.get('minor')) is int and 0<=board['minor']<2**20,'board input character-device join absent')
