# SPDX-License-Identifier: MIT
"""Fixed US qcode plans. No PTY, guest execution, clipboard or callback channel."""
import hashlib
import json
import re
import time

STEPS=('launch','workspace','shell','editor-open','editor-type','editor-save','editor-quit','result','close')
VIEWS=('shell','editor','result')
FRAMES=tuple(s+'-'+v for s in ('minimal','overlay') for v in VIEWS)
STATUS='PASS_MANAGED_VIRTUAL_KEYBOARD_METADATA'
# Declared conservative generic-VM test policy; never a measured input latency claim.
DELIVERY_POLICY=dict(name='vm-chord-batch-workspace-v1',batch='press-release',gap_ms=500,initial_settle_ms=10000)


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
        'workspace':'cd '+workspace+'\n',
        'shell':"export PS1='keyboard> '; printf 'shell-"+nonce+"\\n' | tee shell.txt\n",
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
    def event(key,down):return dict(type='key',data=dict(down=down,key=dict(type='qcode',data=key)))
    for chord in chords:
        need(type(chord) is list and 1<=len(chord)<=2 and all(type(key) is str for key in chord) and
             len(set(chord))==len(chord),'bounded unique chord required')
        events=[event(key,True) for key in chord]+[event(key,False) for key in reversed(chord)]
        try:
            # The pinned QMP handler syncs once after the complete list: one virtio report.
            qmp.execute('input-send-event',{'events':events});calls+=1
        except BaseException:
            try:qmp.execute('input-send-event',{'events':[event(key,False) for key in reversed(chord)]})
            except BaseException:pass  # The uncertain primary reply stays fatal; no input retry.
            raise
        pause(DELIVERY_POLICY['gap_ms']/1000)
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
                   plan_sha256=sha(encoded(chords)),chords=len(chords),qmp_calls=count,key_events=sum(2*len(c) for c in chords),
                   route='input-send-event/virtio-keyboard-pci',all_keys_released=True,delivery_policy=dict(DELIVERY_POLICY))
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


def verify_startup(proof):
    """Only anonymous, quiescent surfaces owned by this compositor/XWayland."""
    need(type(proof) is dict,'startup ownership proof required')
    compositor=proof.get('compositor');owner=proof.get('owner');rows=proof.get('records')
    def process(row,executable):
        need(type(row) is dict and type(row.get('pid')) is int and 0<row['pid']<2**32 and
             row.get('uid')==[23001]*4 and row.get('executable')==executable and
             type(row.get('starttime')) is int and row['starttime']>0 and
             type(row.get('parent_pid')) is int and row['parent_pid']>0,'startup process identity differs')
    process(compositor,'/usr/bin/Hyprland')
    need(type(rows) is list and len(rows)<=2 and all(type(r) is dict for r in rows),'bounded startup clients required')
    if not rows:
        need(owner is None,'unjoined startup owner');return
    if owner!=compositor:
        process(owner,'/usr/bin/Xwayland');need(owner['parent_pid']==compositor['pid'],'foreign XWayland owner')
    fixed=dict(mapped=False,visible=False,hidden=False,xwayland=True,at=[0,0],size=[0,0],monitor=-1,
               workspace=dict(id=-1,name=''),focusHistoryID=-1,floating=False,pinned=False,fullscreen=0,
               fullscreenClient=0,**{'class':'','title':'','initialClass':'','initialTitle':''})
    addresses=set()
    for row in rows:
        need(type(row.get('pid')) is int and row['pid']==owner['pid'] and
             all(type(row.get(k)) is type(v) and row[k]==v for k,v in fixed.items()),'preexisting application window refused')
        address=row.get('address')
        need(type(address) is str and re.fullmatch('0x[0-9a-f]{1,16}',address) and int(address,16)>0 and address not in addresses,
             'startup surface address duplicate/invalid')
        addresses.add(address)
