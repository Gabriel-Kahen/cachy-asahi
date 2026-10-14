# SPDX-License-Identifier: MIT
"""Recognize pinned Wayland1.23.1 client trace; missing evidence fails closed."""
import re
from decimal import Decimal

def need(ok,reason):
    if not ok:raise ValueError(reason)

LINE=re.compile(r'^\[\s*\d+\.\d{3}\] (?:\{[^}\n]{1,64}\} )?(.*)$')
CALL=re.compile(r'^([a-z0-9_]+)#([1-9][0-9]*)\.([a-z0-9_]+)\((.*)\)$')

class Trace:
    def __init__(self,namespace,layer):
        self.namespace=namespace;self.layer=layer;self.layer_id=self.surface=None;self.configure=None;self.acked=self.attached=self.committed=False
        self.pointer=self.seat=None;self.seat_pointer=False;self.enter=None;self.enter_callback=False;self.motions=[];self.buttons=[];self.events=0
        self.layer_destroyed=self.surface_destroyed=self.retirement_ack=False;self.retirement_callback=None
    def line(self,line):
        need(len(line)<=4096 and self.events<8192,'finite protocol trace');self.events+=1
        match=LINE.fullmatch(line)
        if not match:return
        body=match[1].strip();send=body.startswith('-> ')
        if send:body=body[3:]
        if body.startswith('discarded '):return
        call=CALL.fullmatch(body)
        if not call:return
        interface,obj,method,args=call.groups();obj=int(obj)
        need(obj<2**32,'uint32 traced object ID')
        need(not (interface=='wl_display' and method=='error'),'Wayland trace protocol error')
        if send and interface=='zwlr_layer_shell_v1' and method=='get_layer_surface':
            expected=r'new id zwlr_layer_surface_v1#(\d+), wl_surface#(\d+), wl_output#\d+, '+str(self.layer)+r', "'+self.namespace+r'"'
            m=re.fullmatch(expected,args)
            if m:
                need(self.layer_id is None,'one traced overlay')
                ids=tuple(map(int,m.groups()));need(all(0<i<2**32 for i in ids),'uint32 selected overlay IDs');self.layer_id,self.surface=ids
        elif not send and interface=='zwlr_layer_surface_v1' and obj==self.layer_id and method=='configure':
            m=re.fullmatch(r'(\d+), 320, 240',args);need(m is not None,'exact overlay configure dimensions');self.configure=int(m[1])
        elif send and interface=='zwlr_layer_surface_v1' and obj==self.layer_id and method=='ack_configure':
            need(self.configure is not None and args==str(self.configure),'overlay ack serial');self.acked=True
        elif send and interface=='wl_surface' and obj==self.surface and method=='attach':
            if re.fullmatch(r'wl_buffer#\d+, 0, 0',args):need(self.acked,'buffer after configure ack');self.attached=True
        elif send and interface=='wl_surface' and obj==self.surface and method=='commit':
            if self.attached:self.committed=True
        elif send and interface=='zwlr_layer_surface_v1' and obj==self.layer_id and method=='destroy':
            need(args=='' and self.committed and not self.layer_destroyed,'retire configured committed overlay once');self.layer_destroyed=True
        elif send and interface=='wl_surface' and obj==self.surface and method=='destroy':
            need(args=='' and self.layer_destroyed and not self.surface_destroyed,'selection surface after layer retirement once');self.surface_destroyed=True
        elif send and interface=='wl_display' and obj==1 and method=='sync' and self.layer_destroyed and self.surface_destroyed:
            m=re.fullmatch(r'new id wl_callback#([1-9][0-9]*)',args)
            need(m is not None and self.retirement_callback is None and int(m[1])<2**32,'one post-retirement sync');self.retirement_callback=int(m[1])
        elif not send and interface=='wl_callback' and obj==self.retirement_callback and method=='done':
            need(re.fullmatch(r'\d+',args) is not None and int(args)<2**32 and not self.retirement_ack,'retirement sync done payload');self.retirement_ack=True
        elif not send and interface=='wl_seat' and method=='capabilities':
            need(re.fullmatch(r'\d+',args) is not None,'trace seat bits');self.seat=obj;self.seat_pointer=bool(int(args)&1)
        elif send and interface=='wl_seat' and obj==self.seat and method=='get_pointer':
            m=re.fullmatch(r'new id wl_pointer#(\d+)',args);need(self.seat_pointer and m is not None,'real slurp advertised pointer');self.pointer=int(m[1])
        elif not send and interface=='wl_pointer' and obj==self.pointer:
            if method=='enter':
                m=re.fullmatch(r'(\d+), wl_surface#(\d+), (-?\d+\.\d{8}), (-?\d+\.\d{8})',args)
                need(m is not None and int(m[2])==self.surface,'pointer enters actual selection surface')
                self.enter=(int(m[1]),Decimal(m[3]),Decimal(m[4]))
            elif method=='motion':
                m=re.fullmatch(r'\d+, (-?\d+\.\d{8}), (-?\d+\.\d{8})',args);need(m is not None,'pointer motion trace');self.motions.append(tuple(Decimal(x) for x in m.groups()))
            elif method=='button':
                m=re.fullmatch(r'\d+, \d+, 272, ([01])',args);need(m is not None,'real left-button trace');self.buttons.append(int(m[1]))
            elif method=='leave':self.enter=None;self.enter_callback=False
        elif send and self.enter is not None:
            serial=self.enter[0]
            if interface=='wl_pointer' and obj==self.pointer and method=='set_cursor' and args.startswith(str(serial)+', '):self.enter_callback=True
            if interface=='wp_cursor_shape_device_v1' and method=='set_shape' and re.fullmatch(str(serial)+r', \d+',args):self.enter_callback=True
    def ready(self,x,y):
        return self.committed and self.seat_pointer and self.enter_callback and self.enter is not None and self.enter[1:]==(Decimal(x)+Decimal('.5'),Decimal(y)+Decimal('.5'))
    @property
    def retired(self):return self.layer_destroyed and self.surface_destroyed and self.retirement_ack
