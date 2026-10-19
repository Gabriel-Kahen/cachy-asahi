"""Counted old preparer/init/QEMU extension, original disks/bounds unmodified."""
import ast,inputs
P,C,_,_=inputs.broker()
def init(raw):
 text=raw.decode();tree=ast.parse(text);node=next(n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='INIT'for t in n.targets));old=ast.literal_eval(node.value)
 start=old.index('mount -t ext4 -o rw,nosuid,nodev /dev/vdb /volume\n');end=old.index('for point in /source /inputs;',start)
 new=old[:start]+old[end:];new=new.replace('for point in /source /inputs;','for point in /source /inputs /immutable /immutable-inputs /broker-authorities;').replace('exec /usr/bin/python3 -I -B /debian-maintained-installed16k/guest.py','exec /usr/bin/python3 -I -B /immutable/entry.py')
 P.need(old.count('exec /usr/bin/python3 -I -B /debian-maintained-installed16k/guest.py')==1,'one source-owned init entry');return new,dict(original=P.pin(old.encode()),proposed=P.pin(new.encode()),held_prefix='EXACT_ORIGINAL_PROC_SYS_DEVTMPFS_TMP_RUN',removed='OLD_SHARED_VOLUME_SETUP_NOW_EXACT_PID1_BOOTSTRAP_SEPARATE_SOURCE',worker='NEW_EXPLICIT_PURPOSE_NOT_OLD_VM_ACCEPTANCE')

def preparer(raw):
 text=raw.decode();before="    (boot/'init-debian-maintained-installed16k').write_text(INIT);(boot/'init-debian-maintained-installed16k').chmod(0o755)"
 after="    runtime_stage.execute(boot,volume,Path('/held'),index,Path('/immutable-bundle'),runtime_policy)\n"+before
 P.need(text.count(before)==1,'one original pre-mkfs stage seam');new=text.replace(before,after);P.need(new.replace(after,before)==text,'whole preparer body inverse');return new

def qemu(original,kernel,boot,work,source,hashed):
 argv=original(kernel,boot,work);P.need(argv.count('-append')==1 and argv[argv.index('-m')+1]=='4096'and argv[argv.index('-smp')+1]=='2','original finite QEMU argv')
 index=argv.index('-append')+1;P.need(argv[index]=='console=ttyAMA0 root=/dev/vda ro rootwait init=/init-debian-maintained-installed16k caa_debian_maintained_installed16k=1 arm64.nomops','whole original boot cmdline');argv[index]+=' caa_gnu_verity_bootstrap=1 caa_gnu_immutable_runtime=1'
 for name,path in(('source',source),('hash',hashed)):argv+=['-drive','if=none,id='+name+',format=raw,readonly=on,file='+str(path),'-device','virtio-blk-pci,drive='+name]
 return argv
