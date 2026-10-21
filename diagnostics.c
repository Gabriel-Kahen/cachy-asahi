/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
static void need(int ok,const char *why) { if(!ok) { perror(why); exit(1); } }
static void save(const char *out,const char *name,const char *raw,size_t size) {
 char path[4096]; need(snprintf(path,sizeof(path),"%s/%s",out,name)<(int)sizeof(path),"output path");
 int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);need(fd>=0,"fresh diagnostic");
 while(size) { ssize_t n=write(fd,raw,size);need(n>0,"diagnostic write");raw+=n;size-=n; } need(close(fd)==0,"diagnostic close");
}
static void capture(const char *out,const char *name,const char *path) {
 char raw[1024*1024];int fd=open(path,O_RDONLY|O_CLOEXEC);ssize_t total=0;
 if(fd<0) { int n=snprintf(raw,sizeof(raw),"UNREADABLE errno=%d\n",errno);save(out,name,raw,n);return; }
 for(;;) { ssize_t n=read(fd,raw+total,sizeof(raw)-total);if(n<0) { int error=errno;(void)close(fd);int count=snprintf(raw,sizeof(raw),"UNREADABLE errno=%d\n",error);save(out,name,raw,count);return; }if(!n)break;total+=n;need(total<(ssize_t)sizeof(raw),"diagnostic bound"); }
 need(close(fd)==0,"diagnostic read close");save(out,name,raw,total);
}
static void denied_chroot(const char *out) {
 int p[2];need(pipe2(p,O_CLOEXEC)==0,"chroot probe pipe");pid_t child=fork();need(child>=0,"chroot probe fork");
 if(child==0) { close(p[0]);int r=chroot("/usr"),error=errno;int row[2]={r,error};ssize_t sent;do { sent=write(p[1],row,sizeof(row)); } while(sent<0&&errno==EINTR);if(sent!=(ssize_t)sizeof(row))_exit(2);_exit(r<0&&error==EPERM?0:1); }
 close(p[1]);struct pollfd f={.fd=p[0],.events=POLLIN};int ready=poll(&f,1,3000);
 if(ready!=1) { (void)kill(child,SIGKILL);(void)waitpid(child,NULL,0);need(0,"bounded chroot child"); }
 int row[2],status;need(read(p[0],row,sizeof(row))==(ssize_t)sizeof(row),"chroot denial row");need(close(p[0])==0&&waitpid(child,&status,0)==child,"chroot child retired");
 need(WIFEXITED(status)&&WEXITSTATUS(status)==0&&row[0]==-1&&row[1]==EPERM,"chroot denied outside userns");
 const char raw[]="{\"status\":\"CHROOT_DENIED_EPERM_OUTSIDE_USERNS\",\"owned_child_reaped\":true}\n";save(out,"outside-chroot.json",raw,sizeof(raw)-1);
}
static int option(const char *options,const char *name) {
 size_t size=strlen(name);const char *p=options;
 while(*p) { const char *end=strchr(p,',');size_t n=end?(size_t)(end-p):strlen(p);if(n==size&&memcmp(p,name,n)==0)return 1;if(!end)break;p=end+1; }return 0;
}
static void scratch_mount(const char *path,int noexec) {
 FILE *maps=fopen("/proc/self/mountinfo","re");need(maps!=NULL,"scratch mountinfo");char *line=NULL;size_t capacity=0,total=0;int found=0;
 while(getline(&line,&capacity,maps)>=0) {
  total+=strlen(line);need(total<=1024*1024,"bounded scratch mountinfo");char *sep=strstr(line," - ");need(sep!=NULL,"mount separator");
  char mountpoint[256],options[1024],fs[64];need(sscanf(line,"%*u %*u %*s %*s %255s %1023s",mountpoint,options)==2&&sscanf(sep+3,"%63s",fs)==1,"mount fields");
  if(strcmp(mountpoint,path))continue;
  found++;need(!strcmp(fs,"tmpfs")&&option(options,"rw")&&option(options,"nosuid")&&option(options,"nodev")&&option(options,"noexec")==noexec,"exact original scratch mount restrictions");
 }
 free(line);need(fclose(maps)==0&&found==1,"one scratch tmpfs");
}
static void scratch(const char *path,mode_t mode,int owned) {
 scratch_mount(path,owned);struct stat before,after;need(lstat(path,&before)==0&&S_ISDIR(before.st_mode)&&(before.st_mode&07777)==mode,"private scratch mode");
 need(!owned||(before.st_uid==getuid()&&before.st_gid==getgid()),"private scratch owner");
 char file[256];need(snprintf(file,sizeof(file),"%s/caa-probe-%ld",path,(long)getpid())<(int)sizeof(file),"scratch path");
 int fd=open(file,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);need(fd>=0,"scratch create");const char value[]="exact scratch\n";char raw[sizeof(value)];
 need(write(fd,value,sizeof(value))==(ssize_t)sizeof(value)&&lseek(fd,0,SEEK_SET)==0&&read(fd,raw,sizeof(raw))==(ssize_t)sizeof(raw)&&memcmp(value,raw,sizeof(raw))==0,"scratch full I/O");
 need(close(fd)==0&&unlink(file)==0&&lstat(path,&after)==0,"scratch retirement");need(before.st_dev==after.st_dev&&before.st_ino==after.st_ino&&before.st_mode==after.st_mode&&before.st_uid==after.st_uid&&before.st_gid==after.st_gid,"scratch stable identity");
}
int main(int argc,char **argv) {
 int control=argc==3&&strcmp(argv[1],"--control")==0;need(control||argc==1,"fixed diagnostic invocation");need(getuid()>0&&getuid()==geteuid()&&getgid()==getegid(),"ordinary caller");
 const char *out=control?argv[2]:"/out";capture(out,"proc-status.txt","/proc/self/status");capture(out,"proc-mountinfo.txt","/proc/self/mountinfo");capture(out,"lsm-current.txt","/proc/self/attr/current");capture(out,"lsm-list.txt","/sys/kernel/security/lsm");capture(out,"unprivileged-userns.txt","/proc/sys/kernel/unprivileged_userns_clone");capture(out,"apparmor-userns.txt","/proc/sys/kernel/apparmor_restrict_unprivileged_userns");capture(out,"max-user-namespaces.txt","/proc/sys/user/max_user_namespaces");denied_chroot(out);
 if(control)return 0;
 need(getuid()==1001&&getgid()==1001,"same original ordinary uid");scratch("/run",0700,1);scratch("/var/tmp",01777,0);
 const char raw[]="{\"status\":\"PRIVATE_SCRATCH_REAL_IO_AND_STABLE_IDENTITY\",\"paths\":[\"/run\",\"/var/tmp\"]}\n";save(out,"scratch.json",raw,sizeof(raw)-1);
 char *args[]={"/held-probe","--native-preflight",NULL};execv(args[0],args);need(0,"exec unchanged58 probe");return 1;
}
