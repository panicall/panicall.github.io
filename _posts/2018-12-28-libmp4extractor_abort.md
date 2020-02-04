---
layout: default
author: juwei lin
date: 2018-12-28 16:44:00 +0800
---

# Android 9 Remote DOS in libmp4extractor 

## Overview
In libmp4extractor module, there are many functions calling macro `CHECKxxx` to verify if it is healthy now. Parsing some malformed mp4 file may trigger this CHECK and lead to process mediaextractor abort.  

## Root Cause Analysis
In function `MPEG4Source::parseClearEncryptedSizes` in frameworks/av/media/extractors/mp4/MPEG4Extractor.cpp:  

```
status_t MPEG4Source::parseClearEncryptedSizes(off64_t offset, bool isSubsampleEncryption, uint32_t flags) {

    int ivlength;
    CHECK(mFormat.findInt32(kKeyCryptoDefaultIVSize, &ivlength));
```
Function parseClearEncryptedSizes can be called during mp4 file parsing. And my provided mp4 file doesn't meet the check condition here leading to process abort.

## PoC
I provided the crash mp4 file and the test harness tool `stagefright` arm64 version.  
Reproduce:  
1. copy provided stagefright to your root 64 bit android device.
2. copy the mp4 file to your android device /data folder.
3. run: stagefright -e /data/mp4_check.mp4

I also provide the tombstone file for reference.

## Q & A
### How did you find this vulnerability?
by fuzzing.

### Can you identify exploitability?
This is a remote DOS case.

### Can you identify root cause?
Yes, see the root cause analysis.

### Vulnerable software and hardware
Module: libmp4extractor.so  
Android 9 and All before.