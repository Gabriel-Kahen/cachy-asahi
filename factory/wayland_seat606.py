# SPDX-License-Identifier: MIT
"""Current606 private 16 KiB virtual keyboard seat. No key injection."""
import ast
import json
import os
from pathlib import Path
import re
import shutil
import stat

NAME = 'qemu-virtio-keyboard'
KERNEL_NAME = 'QEMU Virtio Keyboard'
DRIVER = 'virtio_input'
EVENT = 'current606_wayland_keyboard_seat'
MODES = {'pci': 'virtio-keyboard-pci', 'mmio': 'virtio-keyboard-device'}


def need(ok, why):
    if not ok:
        raise ValueError(why)


def normalize(keyboards, device, properties, transport):
    need(transport in MODES, 'exact virtual keyboard transport required')
    need(type(keyboards) is list and len(keyboards) == 1 and type(keyboards[0]) is dict,
         'one actual Hyprland virtual keyboard required')
    keyboard = keyboards[0]
    need(keyboard.get('name') == NAME and keyboard.get('layout') == 'us' and keyboard.get('capsLock') is False,
         'actual Hyprland US virtual keyboard differs')
    need(type(device) is dict and set(device) == {'name','driver','address','event','major','minor','key_bitmap'}
         and device['name'] == KERNEL_NAME and device['driver'] == DRIVER
         and type(device['major']) is int and device['major'] == 13
         and type(device['minor']) is int and 64 <= device['minor'] < 2**20
         and re.fullmatch(r'event[0-9]{1,5}',device['event']) is not None,
         'exact virtual keyboard evdev identity required')
    address = device['address']
    pci = r'/sys/devices/platform/[^/]+/pci[0-9a-f]{4}:[0-9a-f]{2}(?:/[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7])+/virtio[0-9]+'
    mmio = r'/sys/devices/platform/[0-9a-f]+\.virtio_mmio/virtio[0-9]+'
    need(re.fullmatch(pci if transport == 'pci' else mmio,address) is not None,
         'keyboard is off the exact virtual transport')
    bitmap = device['key_bitmap']
    need(type(bitmap) is str and re.fullmatch(r'[0-9a-f]{1,16}(?: [0-9a-f]{1,16}){0,11}',bitmap),
         'bounded ARM64 keyboard capability bitmap required')
    first = int(bitmap.split()[-1],16)
    need(first & (1<<30) and first & (1<<28),'kernel keyboard lacks KEY_A or KEY_ENTER')
    need(properties.get('ID_INPUT_KEYBOARD') == '1' and properties.get('ID_SEAT','seat0') == 'seat0'
         and properties.get('DEVNAME') == '/dev/input/'+device['event']
         and properties.get('MAJOR') == str(device['major']) and properties.get('MINOR') == str(device['minor']),
         'same actual udev keyboard and default seat required')
    return dict(transport=transport, keyboard=dict(name=NAME,layout='us',caps_lock=False), device=device,
                udev={k:properties[k] for k in ('DEVNAME','MAJOR','MINOR','ID_INPUT_KEYBOARD')},
                seat='seat0', key_injection='NOT_RUN', physical_input='NOT_RUN')


def owned_devices(input_root=Path('/sys/class/input'), node_root=Path('/dev/input')):
    def read(path):
        with path.open('rb') as stream:
            raw=stream.read(257)
        need(0<len(raw)<=256,'bounded ordinary keyboard metadata')
        return raw.decode('ascii').strip()

    events = sorted(p for p in input_root.glob('event*') if re.fullmatch(r'event[0-9]{1,5}',p.name))
    need(len(events)<=16,'bounded actual guest evdev namespace')
    devices=[]
    for entry in events:
        point=(entry/'device').resolve(strict=True)
        name=read(point/'name')
        if name != KERNEL_NAME:
            continue
        parents=[p for p in point.parents if re.fullmatch(r'virtio[0-9]+',p.name)]
        need(len(parents)==1,'one actual virtio input ancestor required')
        device=parents[0]
        driver=(device/'driver').resolve(strict=True)
        need(driver==Path('/sys/bus/virtio/drivers/virtio_input'),'actual virtio_input kernel driver required')
        meta=(node_root/entry.name).lstat()
        need(stat.S_ISCHR(meta.st_mode),'actual keyboard event character node required')
        major,minor=os.major(meta.st_rdev),os.minor(meta.st_rdev)
        need(read(entry/'dev')==f'{major}:{minor}','same sysfs and character device identity required')
        devices.append(dict(name=name,driver=driver.name,address=str(device),event=entry.name,major=major,
                            minor=minor,key_bitmap=read(point/'capabilities/key')))
    need(len(devices)==1,'one actual guest QEMU Virtio Keyboard evdev device required')
    return devices[0]


def observe(command, transport):
    devices=json.loads(command(['/usr/bin/hyprctl','-j','devices'],'private-keyboard-seat'))
    need(type(devices) is dict,'actual compositor devices JSON required')
    node=owned_devices()
    argv=['/usr/bin/udevadm','info','--query=property','--name=/dev/input/'+node['event']]
    raw=command(argv,'private-keyboard-udev')
    need(len(raw.encode())<=8192,'bounded actual keyboard udev properties required')
    properties={}
    for line in raw.splitlines():
        key,sep,value=line.partition('=')
        need(sep=='=' and key not in properties,'unique actual udev keyboard properties required')
        properties[key]=value
    return normalize(devices.get('keyboards'),node,properties,transport)


def validate(events, profile, transport):
    rows=[e for e in events if e.get('event')==EVENT]
    need(len(rows)==1 and rows[0]['stage']==profile,'one actual selected Wayland keyboard seat required')
    row=rows[0];value=row['proof'];keyboard=value['keyboard']
    normalized=normalize([dict(name=keyboard['name'],layout=keyboard['layout'],capsLock=keyboard['caps_lock'])],
                         value['device'],dict(value['udev'],ID_SEAT=value['seat']),transport)
    boot=next(i for i,e in enumerate(events) if e.get('event')=='boot')
    visible=next(i for i,e in enumerate(events) if e.get('event')=='frame_ready' and e.get('stage')==profile)
    need(value==normalized and boot<events.index(row)<visible,'actual private keyboard seat and GUI order differ')
    return value


def runtime(text, transport, once):
    need(transport in MODES,'exact virtual keyboard transport required')
    anchor='-device virtio-gpu-pci,id=gpu,xres=1024,yres=768'
    args=' -device '+MODES[transport]+',id=keyboard'
    if transport=='mmio':
        args=' -global virtio-mmio.force-legacy=false'+args
    edited=once(text,anchor,anchor+args)
    need(edited.count(MODES[transport])==1,'one exact virtual keyboard in the selected VM')
    return edited


def apply(out, selected, transport, pin, once):
    need(selected in ('minimal','overlay') and transport in MODES,'exact ARM16K seat profile required')
    changes={}
    def edit(name, fn):
        leaf=out/name
        old=leaf.read_text()
        new=fn(old)
        if leaf.suffix=='.py':
            ast.parse(new)
        leaf.write_text(new)
        changes[name]=dict(before=pin(old.encode()),after=pin(new.encode()))

    edit('desktop574_runtime.py',lambda s:runtime(s,transport,once))
    # The session probes the compositor it just connected to, with the existing healthy owner checks.
    anchor="        lock=json.loads(C.read(base.SHARE/'candidate-lock.json'))"
    seat=("        keyseat=load('_current606_private_wayland_seat','wayland_seat606.py')\n"
          f"        base.emit({EVENT!r},stage=stage,proof=keyseat.observe(command,{transport!r}))\n")
    edit('session.py',lambda s:once(s,anchor,seat+anchor))
    anchor='cp /runner/welcome8_stop.py'
    edit('desktop574_fixture.sh',lambda s:once(s,anchor,
         'cp /runner/wayland_seat606.py "$root/usr/local/share/desktop574/"\n'+anchor))
    tail=("\n_wayland_seat_full_gui=verify_result\ndef verify_result(events,lock):\n"
          "    import wayland_seat606\n"
          f"    seat=wayland_seat606.validate(events,{selected!r},{transport!r})\n"
          "    return dict(_wayland_seat_full_gui(events,lock),wayland_keyboard_seat=seat)\n")
    edit('contract.py',lambda s:s+tail)
    shutil.copyfile(Path(__file__),out/'wayland_seat606.py')
    return changes
