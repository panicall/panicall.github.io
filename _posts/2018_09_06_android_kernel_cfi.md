---
layout: default
author: juwei lin
date: 2018-09-06 17:53:00 +0800
---

## What is CFI?

[Kernel CFI](https://source.android.com/devices/tech/debug/kcfi)

> Control flow integrity (CFI) is a security mechanism that disallows changes to the original control flow graph of a compiled binary, making it significantly harder to perform such attacks.
> In Android 9, we enabled LLVM's implementation of CFI in more components and also in the kernel. System CFI is on by default, but you need to enable kernel CFI.
> Support for kernel CFI exists in Android common kernel versions 4.9 and 4.14.
> For Android P, CFI is enabled by default widely within the media frameworks and other security-critical components, such as NFC and Bluetooth. CFI kernel support has also been introduced into the Android common kernel when building with LLVM, providing the option to further harden the trusted computing base. 
>

Other important reference materials:  
[Control Flow Integrity Design Documentation](https://clang.llvm.org/docs/ControlFlowIntegrityDesign.html)  
[Compiler-based security mitigations in Android P](https://android-developers.googleblog.com/2018/06/compiler-based-security-mitigations-in.html)  

## Build a kernel with CFI
1. create a standalone toolchain
   I created a toolchain of type arm64:
   ```
   $NDK/build/tools/make_standalone_toolchain.py \
        --arch arm64 --api 28 --install-dir /tmp/my-arm64-toolchain
   ``` 
2. download goldfish source code
   skip. You can refer [here](./posts/2018_09_06_android_kernel_kasan.html)
3. enable CFI in defconfig
   * copy defconfig(goldfish/arch/arm64/configs/) to cfi_defconfig.
   * add these lines:
    ```
    CONFIG_LTO_CLANG=y
    CONFIG_CFI_CLANG=y
    ```
4. make sure your swap file > 10GB
   ```
   # Make all swap off
   sudo swapoff -a

   # Resize the swapfile
   sudo dd if=/dev/zero of=/swapfile bs=1M count=10240

   # Make swapfile usable
   sudo mkswap /swapfile

   # Make swapon again
   sudo swapon /swapfile
   ```

5. build kernel with cfi
   ```
   PATH=$PATH:/path/to/my-arm64-toolchain/bin/
   export CROSS_COMPILE=aarch64-linux-android-
   export ARCH=arm64
   make CC="/path/to/my-arm64-toolchain/bin/clang" CLANG_TRIPLE=aarch64-linux-gnu-
   ```
  
   Please be noticed that, if missing LLVMgold.so and libstd++.so.1, please copy these 2 files into /usr/lib from your toolchain.

6. vmlinxu with CFI ON  
   After successfully build, vmlinux can be found [here](https://adc.github.trendmicro.com/CoreTech-MARS/allexp/tree/master/resource/bin/android_kernel/goldfish_4.9_dev/arm64/cfi) .

## CFI in Android 
### overview  
There are 3 major [CFI check types](https://clang.llvm.org/docs/ControlFlowIntegrityDesign.html): 
* Forward-Edge CFI for Virtual Calls
* Forward-Edge CFI for Indirect Function Calls
* Backward-edge CFI for return statements (RCFI)
    
CFI will do runtime check in the above 3 type positions. In current Android kernel(4.9), we will investigate the first 2 types.

### insight
Android kernel CFI(Forward-Edge CFI) consists of two parts: fast path check and slow path check. See the following picture as an example.  
![kernel_cfi]({{site.url}}{{site.baseurl}}/res/kernel_cfi.png)  
This picture illustrates how a function that takes an object and calls a virtual function gets translated into assembly with and without CFI. Actually each check point(foo function here) has its own instrumented unique range value. Another example from my compiled vmlinux:  
![kernel_cfi]({{site.url}}{{site.baseurl}}/res/vmlinux_cfi.png)  
The above picture describes the cfi implementation in Android kernel. It also includes fast path check and slow path check. Fast path check determines if the pointer falls within an expected range of addresses of compatible vtables. Failing that, execution falls through to a slow path that does a more extensive check for valid classes that are defined in other shared libraries. The slow path will abort execution if the vtable pointer points to an invalid target.  
The relationship between fast check and slow check can be found [here](https://clang.llvm.org/docs/ControlFlowIntegrityDesign.html):  
```
In the monolithic scheme a call site is instrumented as
if (!InlinedFastCheck(f))
    abort();
call *f

In the cross-DSO scheme it becomes
if (!InlinedFastCheck(f))
    __cfi_slowpath(CallSiteTypeId, f);
call *f
```  
CallSiteTypeId is the `id` you can see in the above picture. It is for slowpath check. Fast path check is simple which just check the alignment and range. The above picture equals to the following:  
![cfi_check]({{site.url}}{{site.baseurl}}/res/cfi_check.png)  
v4 is a function pointer in array fn_handler, e.g. fn_show_ptregs which locates at 0xFFFF000008E322BC, dummycon_deinit is a value of 0xFFFF000008E322A0. So v4-dummycon_deinit = 0xFFFF000008E322BC - 0xFFFF000008E322A0 = 0x1C, which satisfy both alignment and range check.  
If failed, slowpath check works. Slow path check is implemented in kernel as:  
`void __cfi_slowpath(uint64 CallSiteTypeId, void *TargetAddr)`  
CallSiteTypeId is a 8 bytes long number which is introduced before. This function loads a shadow value for TargetAddr,finds the address of __cfi_check and calls that. The default __cfi_check in Android kernel is a very big function contains lots of valid compatible addresses. See __cfi_check as below:  
```
    .text:FFFF00000808C000                 EXPORT __cfi_check
    .text:FFFF00000808C000 __cfi_check                           
    .text:FFFF00000808C000                 MOV             X8, #0xF484          ;start locating the entry by 
    .text:FFFF00000808C004                 MOVK            X8, #0x3DDE,LSL#16   ;CallSiteTypeId
    .text:FFFF00000808C008                 MOVK            X8, #0xB025,LSL#32
    .text:FFFF00000808C00C                 MOVK            X8, #0xFEAD,LSL#48
    .text:FFFF00000808C010                 CMP             X0, X8
    .text:FFFF00000808C014                 B.GT            loc_FFFF00000808C15C
    .text:FFFF00000808C018                 MOV             X8, #0xC424
    .text:FFFF00000808C01C                 MOVK            X8, #0xBC96,LSL#16
    .text:FFFF00000808C020                 MOVK            X8, #0xC27D,LSL#32
    .text:FFFF00000808C024                 MOVK            X8, #0xBED0,LSL#48
    .text:FFFF00000808C028                 CMP             X0, X8
    .text:FFFF00000808C02C                 B.LE            loc_FFFF00000808C2A0
    .text:FFFF00000808C030                 MOV             X8, #0xB27D
    .text:FFFF00000808C034                 MOVK            X8, #0xAE66,LSL#16
    .text:FFFF00000808C038                 MOVK            X8, #0x6293,LSL#32
    .text:FFFF00000808C03C                 MOVK            X8, #0xDDBE,LSL#48
    .text:FFFF00000808C040                 CMP             X0, X8
    .text:FFFF00000808C044                 B.GT            loc_FFFF00000808C4F8
    .text:FFFF00000808C048                 MOV             X8, #0xB0BA
    .text:FFFF00000808C04C                 MOVK            X8, #0x3794,LSL#16
    .text:FFFF00000808C050                 MOVK            X8, #0x2CA1,LSL#32
    .text:FFFF00000808C054                 MOVK            X8, #0xCDC9,LSL#48
    .text:FFFF00000808C058                 CMP             X0, X8
    .text:FFFF00000808C05C                 B.GT            loc_FFFF00000808CB40
    .text:FFFF00000808C060                 MOV             X8, #0x90FF
    .text:FFFF00000808C064                 MOVK            X8, #0xD5B2,LSL#16
    .text:FFFF00000808C068                 MOVK            X8, #0x5612,LSL#32
    .text:FFFF00000808C06C                 MOVK            X8, #0xC656,LSL#48
    .text:FFFF00000808C070                 CMP             X0, X8
    .text:FFFF00000808C074                 B.LE            loc_FFFF00000808D128
    .text:FFFF00000808C078                 MOV             X8, #0x1A37
    .text:FFFF00000808C07C                 MOVK            X8, #0x99F4,LSL#16
    .text:FFFF00000808C080                 MOVK            X8, #0xEDB0,LSL#32
    .text:FFFF00000808C084                 MOVK            X8, #0xC9F0,LSL#48
    .text:FFFF00000808C088                 CMP             X0, X8
    .text:FFFF00000808C08C                 B.GT            loc_FFFF00000808DF68
    .text:FFFF00000808C090                 MOV             X8, #0x5126
    .text:FFFF00000808C094                 MOVK            X8, #0x3180,LSL#16
    .text:FFFF00000808C098                 MOVK            X8, #0x6735,LSL#32
    .text:FFFF00000808C09C                 MOVK            X8, #0xC836,LSL#48
    .text:FFFF00000808C0A0                 CMP             X0, X8
    .text:FFFF00000808C0A4                 B.LE            loc_FFFF00000808F8E8
    .text:FFFF00000808C0A8                 MOV             X8, #0xC2AA
    .text:FFFF00000808C0AC                 MOVK            X8, #0x7417,LSL#16
    .text:FFFF00000808C0B0                 MOVK            X8, #0xE1FC,LSL#32
    .text:FFFF00000808C0B4                 MOVK            X8, #0xC923,LSL#48
    .text:FFFF00000808C0B8                 CMP             X0, X8
    .text:FFFF00000808C0BC                 B.LE            loc_FFFF0000080925E8
    .text:FFFF00000808C0C0                 MOV             X8, #0x788E
    .text:FFFF00000808C0C4                 MOVK            X8, #0x571D,LSL#16
    .text:FFFF00000808C0C8                 MOVK            X8, #0xACB8,LSL#32
    .text:FFFF00000808C0CC                 MOVK            X8, #0xC989,LSL#48
    .text:FFFF00000808C0D0                 CMP             X0, X8
    .text:FFFF00000808C0D4                 B.LE            loc_FFFF0000080973F4
    .text:FFFF00000808C0D8                 MOV             X8, #0xC19A
    .text:FFFF00000808C0DC                 MOVK            X8, #0xDF3A,LSL#16
    .text:FFFF00000808C0E0                 MOVK            X8, #0xD926,LSL#32
    .text:FFFF00000808C0E4                 MOVK            X8, #0xC9BC,LSL#48
    .text:FFFF00000808C0E8                 CMP             X0, X8
    .text:FFFF00000808C0EC                 B.GT            loc_FFFF00000809F824
    .text:FFFF00000808C0F0                 MOV             X8, #0x89EA
    .text:FFFF00000808C0F4                 MOVK            X8, #0xA29C,LSL#16
    .text:FFFF00000808C0F8                 MOVK            X8, #0x53E6,LSL#32
    .text:FFFF00000808C0FC                 MOVK            X8, #0xC9A8,LSL#48
    .text:FFFF00000808C100                 CMP             X0, X8
    .text:FFFF00000808C104                 B.GT            loc_FFFF0000080AD054
    .text:FFFF00000808C108                 MOV             X8, #0x2763
    .text:FFFF00000808C10C                 MOVK            X8, #0x5163,LSL#16
    .text:FFFF00000808C110                 MOVK            X8, #0x85A1,LSL#32
    .text:FFFF00000808C114                 MOVK            X8, #0xC9A3,LSL#48
    .text:FFFF00000808C118                 CMP             X0, X8
    .text:FFFF00000808C11C                 B.GT            loc_FFFF0000080C20D0
    .text:FFFF00000808C120                 MOV             X8, #0x788F
    .text:FFFF00000808C124                 MOVK            X8, #0x571D,LSL#16
    .text:FFFF00000808C128                 MOVK            X8, #0xACB8,LSL#32
    .text:FFFF00000808C12C                 MOVK            X8, #0xC989,LSL#48
    .text:FFFF00000808C130                 CMP             X0, X8
    .text:FFFF00000808C134                 B.EQ            loc_FFFF0000080DD5F0
    .text:FFFF00000808C138                 MOV             X8, #0x8829
    .text:FFFF00000808C13C                 MOVK            X8, #0xF209,LSL#16
    .text:FFFF00000808C140                 MOVK            X8, #0x19E0,LSL#32
    .text:FFFF00000808C144                 MOVK            X8, #0xC999,LSL#48
    .text:FFFF00000808C148                 CMP             X0, X8
    .text:FFFF00000808C14C                 B.NE            loc_FFFF0000080DD5FC
    .text:FFFF00000808C150                 ADRP            X8, #get_cpu_device@PAGE         ;start checking if  
    .text:FFFF00000808C154                 ADD             X8, X8, #get_cpu_device@PAGEOFF  ;TargetAddr equals with
    .text:FFFF00000808C158                 B               loc_FFFF00000810C6AC             ;get_cpu_device
    ...
    ...
    ...
    .text:FFFF00000810C1FC locret_FFFF00000810C1FC               
    .text:FFFF00000810C1FC                                        
    .text:FFFF00000810C1FC                 RET
    ...
    ...
    ...
    .text:FFFF00000810C6AC loc_FFFF00000810C6AC                   
    .text:FFFF00000810C6AC                                     
    .text:FFFF00000810C6AC                 CMP             X1, X8
    .text:FFFF00000810C6B0                 B.EQ            locret_FFFF00000810C1FC
    .text:FFFF00000810C6B4
    .text:FFFF00000810C6B4 loc_FFFF00000810C6B4          
    .text:FFFF00000810C6B4                                     
    .text:FFFF00000810C6B4                 MOV             X0, X2
    .text:FFFF00000810C6B8                 BL              __cfi_check_fail
    .text:FFFF00000810C6B8 ; End of function __cfi_check
```  
It firstly uses id to search the proper entry and then check if the entry's function(get_cpu_device) equals with TargetAddr. If not equal, CFI will break the system.

  
  
  [Back Home]({{site.url}}{{site.baseurl}})