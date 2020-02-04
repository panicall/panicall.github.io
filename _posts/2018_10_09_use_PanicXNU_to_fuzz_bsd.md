---
layout: default
author: juwei lin
date: 2018-10-09 15:16:00 +0800

history: 2019-1-2 add kasan 2, add 4903.221.2
---

# Use PanicXNU to fuzz XNU
**Agenda**  
* Customize XNU to support Sanitizer Coverage, KMSAN, KASAN
* Deliver XNU
* Deliver PanicXNU
* Upgrade
  
## Customize XNU
Basic Process
* [Download Latest XNU Source Code](https://opensource.apple.com/tarballs/xnu/)
* Modify XNU Source to Add Support KASAN, KCOV, KMSAN, UBSAN
* Compile XNU

### Modify XNU
This section is based on XNU-4570-71.2 (macOS 10.13.6)

#### Add Support for Code Coverage
1. add kcov module inside `/osfmk/kern`  
   +[kcov.h](https://adc.github.trendmicro.com/CoreTech-MARS/allexp/blob/master/PanicXNU/CustomXNU/kcov_4570.71.2/osfmk/kern/kcov.h)  
   +[kcov.c](https://adc.github.trendmicro.com/CoreTech-MARS/allexp/blob/master/PanicXNU/CustomXNU/kcov_4570.71.2/osfmk/kern/kcov.c)
2. update task module and structure inside `/osfmk/kern`
   * task.h  
     add `#include "kcov.h"`;  
     at the end of structure `task`, add:  
     ```C
     enum kcov_mode kcov_mode;
	 unsigned	kcov_size;
	 void		*kcov_area;
	 struct kcov	*kcov;
	 uint32_t	refcount;
     ```
     you can get patched task.h of 4570.71.2 [here](https://adc.github.trendmicro.com/CoreTech-MARS/allexp/blob/master/PanicXNU/CustomXNU/kcov_4570.71.2/osfmk/kern/kcov.h)
   * task.c  
     at the end of function `task_terminate_internal`, add `kcov_task_exit(task)`;  
     at the end of function `task_create_internal`, add `kcov_task_init(new_task)`;  
     you can get patched task.c of 4570.71.2 [here](https://adc.github.trendmicro.com/CoreTech-MARS/allexp/blob/master/PanicXNU/CustomXNU/kcov_4570.71.2/osfmk/kern/task.c)
3. update compile config files
   * master file in `/config`
     add kcov device :
     ```
     #
     # kcov device
     pseudo-device	kcov		1	init	kcov_init
     ```
     you can get the master file [here](https://adc.github.trendmicro.com/CoreTech-MARS/allexp/blob/master/PanicXNU/CustomXNU/kcov_4570.71.2/config/MASTER)
   * `files` in `/osfmk/conf/`  
     add `osfmk/kern/kcov.c 	optional kcov`  
     you can get it [here](https://adc.github.trendmicro.com/CoreTech-MARS/allexp/blob/master/PanicXNU/CustomXNU/kcov_4570.71.2/osfmk/conf/files)
   * makefile.template in `/bsd/conf`  
     add `-fsanitize-coverage=trace-pc` into existing CFLAGS  
     you can get it [here](https://adc.github.trendmicro.com/CoreTech-MARS/allexp/blob/master/PanicXNU/CustomXNU/kcov_4570.71.2/bsd/conf/Makefile.template)
   * MakeInc.def in `/makedefs`  
     remove Werror;        
     add `USE_WERROR := 0` 

     if you get warnings like "inlinable function call in a function with debug info must have a !dbg location", you can use this workaround to skip it.  
     `DEBUG_CFLAGS := -g --> DEBUG_CFLAGS := -g0`  
     you can get it [here](https://adc.github.trendmicro.com/CoreTech-MARS/allexp/blob/master/PanicXNU/CustomXNU/kcov_4570.71.2/makedefs/MakeInc.def)
  
#### Add Support for KASAN 1  
(don't use this method; deprecated!)
1. remove instrumentations in `/makedefs/makeinc.def`  
   remove '-fsanitize=address'
   you can get it [here](https://adc.github.trendmicro.com/CoreTech-MARS/allexp/blob/master/PanicXNU/CustomXNU/kcov_4570.71.2/makedefs/MakeInc.def)
2. remove error check `/san/kasan.h`
   at the first of this file, comment :
   ```
   /*
    #if KASAN && !__has_feature(address_sanitizer)
    # error "KASAN selected, but not enabled in compiler"
    #endif
    */
   ```
   you can get it [here](https://adc.github.trendmicro.com/CoreTech-MARS/allexp/blob/master/PanicXNU/CustomXNU/kcov_4570.71.2/san/kasan.h)
  
#### Add Support for KASAN 2  
add the following functions into `{xnu_root_folder}/san/kasan-blacklist-x86_64`:  
```
fun:machine_trace_thread_get_kva
fun:PHYSMAP_PTOV_check
fun:is_ept_pmap
fun:pmap_pde
fun:pltrace
fun:iv_alloc
fun:iv_dealloc
fun:ivace_release
fun:unsafe_convert_port_to_voucher
fun:convert_port_to_voucher
fun:convert_port_name_to_voucher
fun:ipc_voucher_notify
fun:convert_voucher_to_port
fun:ivac_dealloc
fun:convert_port_to_voucher_attr_control
fun:ipc_voucher_attr_control_notify
fun:convert_voucher_attr_control_to_port
fun:iv_dedup
fun:ipc_register_well_known_mach_voucher_attr_manager
fun:mach_voucher_extract_attr_content
fun:ivace_lookup_values
fun:mach_voucher_extract_attr_recipe
fun:mach_voucher_extract_all_attr_recipes
fun:mach_voucher_debug_info
fun:mach_voucher_attr_command
fun:mach_voucher_attr_control_get_values
fun:ipc_get_pthpriority_from_kmsg_voucher
fun:ipc_voucher_send_preprocessing
fun:ipc_voucher_prepare_processing_recipe
fun:ipc_voucher_receive_postprocessing
fun:mach_generate_activity_id
fun:user_data_release_value
fun:user_data_get_value
fun:user_data_extract_content
fun:ivace_reference_by_index
fun:ipc_replace_voucher_value
fun:ivace_reference_by_value
fun:re_queue_tail
fun:host_request_notification
fun:OSMalloc_Tagalloc
fun:OSMalloc_Tagrele
fun:OSMalloc_Tagfree
fun:enqueue_tail
fun:remque
fun:enable_preemption_internal
fun:entry_queue_change_entry
fun:semaphore_create
fun:thread_exception_enqueue
fun:thread_call_func_cancel
fun:_pending_call_enqueue
fun:waitq_select_one_locked
fun:dequeue_head
fun:do_backtrace32
fun:ccdigest_final
fun:ccctr_setctr
fun:ccdrbg_init
fun:ccdrbg_generate
fun:cpu_datap
fun:ccdrbg_reseed
fun:cpu_shadowp
fun:PMAP_ZINFO_PALLOC
fun:pmap_pte
fun:pmap64_pml4
fun:pmap64_user_pml4
fun:PMAP_ZINFO_PFREE
fun:pmap_update_pte
fun:pmap64_pdpt
fun:pmap64_pde
fun:set_dirbase
fun:cpu_is_running
fun:pmap_pcid_validate_current
fun:PV_HASHED_ALLOC
fun:PV_HASHED_KERN_ALLOC
fun:pmap_pv_throttle
fun:pv_hash_add
fun:PV_HASHED_FREE_LIST
fun:PV_HASHED_KERN_FREE_LIST
fun:pv_hash_remove
fun:pmap_classify_pagetable_corruption
fun:DBLMAP_CHECK
fun:LDTALIAS_CHECK
fun:timer_queue_cpu
fun:enqueue_head
fun:bpf_tap_mbuf
fun:icmp_input
fun:flow_divert_kctl_send
fun:au_to_attr
fun:inflate_fast
fun:ivac_alloc
fun:ipc_create_mach_voucher
fun:ipc_voucher_attr_control_create_mach_voucher
fun:mach_voucher_attr_control_create_mach_voucher
fun:host_create_mach_voucher
fun:tlb_flush_global
fun:cpuid
fun:do_cpuid
fun:ipsec_start
fun:necp_assign_client_result
fun:pfr_route_kentry
fun:pfr_unroute_kentry
fun:in6_getsockaddr_s
fun:au_to_arg32
fun:au_to_arg
fun:au_to_attr32
fun:au_to_attr64
fun:au_to_exit
fun:au_to_groups
fun:au_to_newgroups
fun:au_to_in_addr_ex
fun:au_to_ipc
fun:au_to_ipc_perm
fun:au_to_file
fun:au_to_process32
fun:au_to_process64
fun:au_to_process
fun:au_to_process32_ex
fun:au_to_process64_ex
fun:au_to_return32
fun:au_to_return
fun:au_to_seq
fun:au_to_subject32
fun:au_to_subject64
fun:au_to_subject
fun:au_to_subject32_ex
fun:au_to_subject64_ex
fun:au_to_exec_strings
fun:au_to_header32_ex_tm
fun:au_to_header32_tm
fun:au_to_header64_tm
fun:au_to_trailer
fun:so_set_recv_anyif
```

#### Add Support for KMSAN
currently, just memset the allocated memory to magic value `0xDE` at the following locations:
* OSMalloc (/osfmk/kern/kalloc.c)  
* kalloc_canblock (/osfmk/kern/kalloc.c)  
* kmem_alloc (/osfmk/vm/vm_kern.c)  
* kernel_memory_allocate optional (/osfmk/vm/vm_kern.c)  
you can get vm_kern.c [here](https://adc.github.trendmicro.com/CoreTech-MARS/allexp/blob/master/PanicXNU/CustomXNU/kcov_4570.71.2/osfmk/vm/vm_kern.c)  
you can get kalloc.c [here](https://adc.github.trendmicro.com/CoreTech-MARS/allexp/blob/master/PanicXNU/CustomXNU/kcov_4570.71.2/osfmk/kern/kalloc.c)

  
       
  
We also add a syscall to help crash kernel when fuzzer detects any uninitialized memory usage
1. add syscall `panicall_report` in `/bsd/kern/sys_generic.c`
   ```C
    int panicall_report(__unused struct proc *p, struct panicall_report_args *args, __unused int32_t *retval)
    {
        uint32_t syscallid = args->syscallid;
        uint64_t *total_9_args = (uint64_t*)args->total_9_args;
        uint32_t leak_arg_index = args->leak_arg_index;
        uint32_t leak_arg_len = args->leak_arg_len;
        
        if (leak_arg_index > 8)
            return 0;
        
        uint64_t kernel_args[9] = {0};
        copyin((user_addr_t)total_9_args, kernel_args, sizeof(kernel_args));
        
        uint32_t leak_len = leak_arg_len>0x400?0x400:leak_arg_len;
        uint8_t leak_buf[0x400] = {0};
        copyin((user_addr_t)kernel_args[leak_arg_index], leak_buf, leak_len);
        
        char *leak_buffer_msg = NULL;
        MALLOC(leak_buffer_msg, char *, 0x1000, M_TEMP, M_WAITOK | M_ZERO);
        if (leak_buffer_msg == NULL)
            return 0;
        
        leak_buffer_msg[0] = '\0';
        
        char value[10] = {0};
        
        for (uint32_t i=0; i<leak_len; i++)
        {
            memset(value, 0, 10);
            snprintf(value, 10, "%2X",leak_buf[i]);
            strcat(leak_buffer_msg, value);
            
            if (i % 16 == 15)
                strcat(leak_buffer_msg, "\n");
            else
                strcat(leak_buffer_msg, " ");
        }
        
        panic("[panicall] report leak=========\n\
            syscall: %d\n\
            a0: 0x%llx a1: 0x%llx a2: 0x%llx\n\
            a3: 0x%llx a4: 0x%llx a5: 0x%llx\n\
            a6: 0x%llx a7: 0x%llx a8: 0x%llx\n\
            leak arg index: %d\n\
            leak arg len: %d\n\
            \n\
            leak buffer: \n\
            %s\n", 
            syscallid,
            kernel_args[0], kernel_args[1], kernel_args[2], 
            kernel_args[3], kernel_args[4], kernel_args[5], 
            kernel_args[6], kernel_args[7], kernel_args[8], 
            leak_arg_index, 
            leak_arg_len, 
            leak_buffer_msg 
            );
        
        FREE(leak_buffer_msg, M_TEMP);
        
        return 0;
    }
   ```
   you can get it [here](https://adc.github.trendmicro.com/CoreTech-MARS/allexp/blob/master/PanicXNU/CustomXNU/kcov_4570.71.2/bsd/kern/sys_generic.c)
2. update config file `bsd/kern/syscalls.master`
   at the end of this file, add:
   ```
   532	AUE_NULL	ALL	{ int panicall(uint64_t value); } 
   533  AUE_NULL    ALL { int panicall_report(uint32_t syscallid, uint64_t total_9_args, uint32_t leak_arg_index, uint32_t leak_arg_len); }
   ```
   you can get it [here](https://adc.github.trendmicro.com/CoreTech-MARS/allexp/blob/master/PanicXNU/CustomXNU/kcov_4570.71.2/bsd/kern/syscalls.master)
  
#### Add New Syscall
In the previous section, I already add a new syscall named `panicall_report` which is used to help privide leak information by crashing the kernel. In this section , I provide another syscall named `panicall` which can help debug your fuzzer.
```C
int panicall(__unused struct proc *p, struct panicall_args *args, __unused int32_t *retval)
{
	printf("panicall: 0x%x\n", args->value);
	
	if (args->value == 0xffffffff){
		panic("hello, panicall(@panicii) 0xffffffff");
	}
	else if (args->value == 0x12345678) {
		panic("hello, panicall(@panicii) 0x12345678");
	}
	
	return 0;
}
```
you can get it [here](https://adc.github.trendmicro.com/CoreTech-MARS/allexp/blob/master/PanicXNU/CustomXNU/kcov_4570.71.2/bsd/kern/sys_generic.c)

#### Patch Kernel  
There are too many assert failures in `Release` kernel. We need patch the kernel before fuzzing.  
* patch01: tcp_output.c in bsd/netinit  
before patch:
    ```
    VERIFY(inp->inp_flowhash != 0);
    ```
  after patch:
    ```
    // [juwei] added for patch
    if (inp->inp_flowhash == 0)
        inp->inp_flowhash = inp_calc_flowhash(inp);

    VERIFY(inp->inp_flowhash != 0);
    ```

* patch02: mptcp_usrreq.c in bsd/netinit  
    before patch:
    ```
    VERIFY(progress == tot);
    ```

    after patch:
    ```
	if (progress != tot) 	//patched by juwei
	{
		m_freem(m);
		return (EINVAL);
	}
		
	VERIFY(progress == tot);
    ```

* patch03: kern_memorystatus.c in bsd/kern  
    before patch:
    ```
    assert(isSysProc(p));
    ```
    
    after patch:
    ```
    if (!isSysProc(p))	//patch by juwei
        return;
    assert(isSysProc(p));
    ```
* patch04: thread.c in osfmk/kern  
    before patch:
    ```
    assert(percentage <= 100);
    ```

    after patch:
    ```
    if (percentage > 100) //patched by juwei
		return (KERN_INVALID_ARGUMENT);
	assert(percentage <= 100);
    ```
* patch05: ledger.c in osfmk/kern  
    before patch:
    ```
    assert(limit > 0);
    ```
    after patch:
    ```
    if (limit <= 0)	//patched by juwei
		return (KERN_INVALID_VALUE);
	assert(limit > 0);
    ```

* patch06: ledger.c in osfmk/kern  
    before patch:
    ```
    assert((thread->options & TH_OPT_PROC_CPULIMIT) != 0);
    ```
    after patch:
    ```
	if ((thread->options & TH_OPT_PROC_CPULIMIT) == 0) //patched_05 by juwei
		return;
	assert((thread->options & TH_OPT_PROC_CPULIMIT) != 0);
    ```




### Compile XNU
1. Use `xcode 9.4.1` with command line 9.4.1 to compile xnu-4570.71.2
2. The first time, use [this script](https://adc.github.trendmicro.com/CoreTech-MARS/allexp/blob/master/PanicXNU/CustomXNU/scripts/build-xnu-4570.71.2.sh) to compile
3. Not the first time which means you already prepared the env, type `make SDKROOT=macosx ARCH_CONFIGS=X86_64 KERNEL_CONFIGS="DEVELOPMENT"`. You can replace "DEVELOPMENT" with "RELEASE", "DEBUG" or "KASAN"

#### FAQ
1. /Users/juwei_lin/Vuln/myxnu/build-xnu-4570.71.2/dtrace-262.50.12/libelf/xlate.c:31:10: error: 'link.h' file not found with <angled> include; use "quotes" instead  
2. /Users/juwei_lin/Vuln/myxnu/build-xnu-4570.71.2/dtrace-262.50.12/libdwarf/dwarf_incl.h:45:10: error: 'elf.h' file not found with <angled> include; use "quotes" instead  
3. Werror  
disable Werror in file makedefs/MakeInc.def  
4. /Vuln/myxnu/build-xnu-4570.71.2/xnu-4570.71.2/bsd/net/if_ipsec.c:388:15: error: no member named 'ipsec_needs_netagent' in 'struct ipsec_pcb'  
    add a decision branch :
    ```C
    boolean_t
    ipsec_interface_needs_netagent(ifnet_t interface)
    {
	    struct ipsec_pcb *pcb = NULL;

	    if (interface == NULL) {
		    return (FALSE);
	    }

	    pcb = ifnet_softc(interface);

	    if (pcb == NULL) {
		    return (FALSE);
	    }

    #if IPSEC_NEXUS
	    return (pcb->ipsec_needs_netagent == true);
    #endif
	    return false;
    }
    ```  
  
## Deliver XNU
This section is about how to install customized XNU to override existing XNU kernel file.  
1. compile XNU
2. copy compiled XNU bin to `/System/Library/Kernels`
3. disable SIP
   ```
    1. Reboot the Mac and hold down Command + R keys simultaneously after you hear the startup chime, this will boot OS X into Recovery Mode

	1. When the “OS X Utilities” screen appears, pull down the ‘Utilities’ menu at the top of the screen instead, and choose “Terminal”

	2. Type the following command into the terminal then hit return:
	csrutil disable; reboot

    4. You’ll see a message saying that System Integrity Protection has been disabled and the Mac needs to restart for changes to take effect, and the Mac will then reboot itself automatically, just let it boot up as normal
   ```
4. change boot-args  
   `sudo nvram boot-args="debug=0x146 kext-dev-mode=1 kcsuffix=development keepsyms=1"`  
   you can change kernel to `development`, `debug`, `release` or `kasan`.
5. kextcache
   `sudo kextcache -i /`  
   Normally, it will fail with missing symbol `IOSKCopyKextIdentifierWithAddress` which is not open by Apple.  
   OK, let's implement it.
    ```C
    OSSymbol* IOSKCopyKextIdentifierWithAddress(vm_address_t address);
    OSSymbol* IOSKCopyKextIdentifierWithAddress(vm_address_t address) {
        OSSymbol* sym = NULL;
        OSKext* kext = OSKext::lookupKextWithAddress(address);
        if (kext) {
            sym = (OSSymbol*)kext->getIdentifier();
            if (sym) {
                sym->retain();
            }
            kext->release();
        }
        return sym;
    }
    ```
    You can put it in [OSKext.cpp](https://adc.github.trendmicro.com/CoreTech-MARS/allexp/blob/master/PanicXNU/CustomXNU/kcov_4570.71.2/libkern/c%2B%2B/OSKext.cpp).  

6. reboot


## Deliver PanicXNU  
[PanicXNU](https://adc.github.trendmicro.com/CoreTech-MARS/PanicXNU) is a fuzzer based on syzkaller. I ported it to support macOS syscall/iokit/driver fuzzing.  
**Prerequired:**
1. gomail  
   go get gopkg.in/gomail.v2
2. mongodb   
   go get gopkg.in/mgo.v2
3. mysql  
   go get -u github.com/go-sql-driver/mysql
4. mysql db  
   add the following sql schema:  
   ```sql
   DROP TABLE IF EXISTS `panic_logs`;
   CREATE TABLE `panic_logs` (
   `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
   `signature` varchar(255),
   `filename` varchar(255),
   `submit_time` datetime,
   PRIMARY KEY (`id`)
   ) ENGINE=InnoDB DEFAULT CHARSET=latin1;
   ```
5. vm machines  
   setup 8 vm and create snapshot named 'clean' for each one.  
6. setup service server  
   make sure you can connect to server before fuzzing, try ping. Refer to [fuzz iokit](https://adc.github.trendmicro.com/pages/CoreTech-MARS/allexp/posts/2018_10_09_use_PanicXNU_to_fuzz_iokit.html)  
   * mongo server
   * mysql server
  
**Compile PanicXNU:**  
cd to PanicXNU dir:  
`make HOSTOS=darwin HOSTARCH=amd64 TARGETMOD=syscall/iokit/kext` 

**Run PanicXNU:**  

`syz-manager -config=/Users/juwei_lin/go/src/github.com/Panicall/PanicXNU/config/syscall_fusion.cfg -v=5 -debug=false`

## Upgrade  
**2019-01-02**  
script to build xnu-4903.221.2(macOS 10.14.1): [here](https://adc.github.trendmicro.com/CoreTech-MARS/allexp/blob/master/PanicXNU/CustomXNU/scripts/build-xnu-4903.221.2.sh)
  
  [Back Home]({{site.url}}{{site.baseurl}})
