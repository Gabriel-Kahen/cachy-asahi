"""PID1 protocol extends source-only broker by finite fixed lease operations."""
import os,select,socket
import inputs
P,C,_,B=inputs.broker()
class Service:
 def __init__(self,sock,peer,context,leases):self.sock=sock;self.peer=peer;self.context=context;self.leases=leases;self.broker=None;self._failure_phase='NO_VALIDATED_REQUEST';self._failure_seq=0
 def pass_fds(self):C.pid1();return(self.peer.fileno(),)
 def begin(self,pid):
  C.pid1();self.peer.close();self.broker=B.Broker(self.sock,pid,self.context)
 def eof(self):return self.sock.recv(1,socket.MSG_PEEK)==b''
 def once(self):
  C.pid1();b=self.broker;poll=select.poll();poll.register(b.pidfd,select.POLLIN);P.need(not poll.poll(0),'reserved worker alive')
  value,fds=P.receive(self.sock,(b.worker,0,0),0);b.worker_state();b.seq+=1
  P.need(b.seq<=P.MAX_REQUESTS and value.get('purpose')==P.PURPOSE and value.get('nonce')==self.context.value['nonce']and value.get('seq')==b.seq,'ordered authenticated bounded request')
  if value.get('op')=='source':
   P.need(set(value)=={'purpose','nonce','seq','op'},'exact source request')
   self._failure_phase='SOURCE_CONTEXT_CHECK';self._failure_seq=b.seq
   state=self.context.check()
   self._failure_phase='SOURCE_CAPACITY'
   state.update(purpose=P.PURPOSE,nonce=value['nonce'],seq=b.seq,capacity=self.context.capacity())
   self._failure_phase='SOURCE_SEND'
   P.send(self.sock,state,(self.context.fd,self.context.index))
   self._failure_phase='SOURCE_COMPLETE'
  else:
   P.need(set(value)=={'purpose','nonce','seq','op','case'}and value['op']in('lease-open','lease-close')and value['case']in('probe','pristine','modified'),'only fixed proc/dev lease operations')
   _position_prefix='LEASE_'+('OPEN'if value['op']=='lease-open'else'CLOSE')+'_'+value['case'].upper()
   self._failure_phase=_position_prefix+'_CONTEXT_BEFORE';self._failure_seq=b.seq
   self.context.check()
   self._failure_phase=_position_prefix+'_ACTION'
   receipt=self.leases.open(value['case'])if value['op']=='lease-open'else self.leases.close(value['case'])
   self._failure_phase=_position_prefix+'_CONTEXT_AFTER'
   self.context.check()
   self._failure_phase=_position_prefix+'_SEND'
   P.send(self.sock,dict(purpose=P.PURPOSE,nonce=value['nonce'],seq=b.seq,op=value['op'],case=value['case'],receipt=receipt))
   self._failure_phase=_position_prefix+'_COMPLETE'
 def failure_position(self):
  # Last source-validated finite operation only, never raw request data.
  return dict(phase=self._failure_phase,request_seq=self._failure_seq)
 def retired(self,row):
  C.pid1();P.need(row['group_absence_verified']is True,'all worker/descendant groups absent before mount cleanup')
  if self.leases.active is not None:self.leases.close(self.leases.active['case'])
  receipt=self.leases.retired()
  if self.broker:self.broker.close()
  return receipt
