#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
static void show(const char *p){
    char b[256]; int fd=open(p,O_RDONLY); if(fd<0){printf("%s: <missing>\n",p);return;}
    ssize_t n=read(fd,b,sizeof(b)-1); close(fd); if(n<0)n=0; b[n]=0;
    for(int i=0;i<n;i++) if(b[i]=='\n') b[i]=' ';
    printf("%s: %s\n",p,b);
}
int main(void){
    mount("proc","/proc","proc",0,NULL); mount("sysfs","/sys","sysfs",0,NULL);
    printf("=== SLAB INFO ===\n");
    show("/sys/kernel/slab/posix_timers_cache/object_size");
    show("/sys/kernel/slab/posix_timers_cache/objs_per_slab");
    show("/sys/kernel/slab/posix_timers_cache/order");
    show("/sys/kernel/slab/posix_timers_cache/cpu_partial");
    show("/sys/kernel/slab/posix_timers_cache/aliases");
    show("/sys/kernel/slab/posix_timers_cache/objects");
    show("/sys/kernel/slab/posix_timers_cache/slabs");
    show("/sys/devices/system/cpu/online");
    show("/proc/sys/fs/aio-max-nr");
    show("/proc/sys/vm/nr_hugepages");
    DIR *d=opendir("/sys/kernel/slab");
    if(d){ struct dirent *e; printf("slab names: "); while((e=readdir(d))) if(strstr(e->d_name,"posix")) printf("%s ",e->d_name); printf("\n"); closedir(d);}    
    sync(); reboot(RB_POWER_OFF); return 0;
}
