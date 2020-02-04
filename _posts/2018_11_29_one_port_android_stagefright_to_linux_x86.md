---
layout: default
author: juwei lin
date: 2018-11-29 18:08:00 +0800
---

# Fuzz Android Framework ONE: How to port Android StageFright to Linux?

## Modify Linux kernel to enable Android binder and ashmem
1. download kernel source code  
   `$ sudo apt install linux-source`
2. extract source code  
   ```
   $ cd kernel
   $ tar jxvf /usr/src/linux/linux-source-4.8.0.tar.bz2
   $ cd linux-source-4.8.0
   ```
3. copy .config  
   ```
   $ cp -vi /boot/config-`uname -r` .config
   $ make oldconfig
   ```
4. enable binder and ashmem  
   `make menuconfig`  
   Binder: goto Device Drivers->Android, select `Andoid Drivers` and `Android Binder IPC Driver`.  
   ashmem: goto Device Drivers->Staging drivers->Android, select `Enable the Anonymous Shared Memory Subsystem`.  
5. compile  
   ```
   $ make -j16
   $ sudo make modules_install
   $ sudo make install
   ```
6. config udev  
   `$ echo -e "KERNEL==\"binder\", MODE=\"0666\"\nKERNEL==\"ashmem\", MODE=\"0666\"" | sudo tee /etc/udev/rules.d/android.rules`
7. restart  
  
## Modify Stagefright
1. download AOSP
2. apply [patch](https://adc.github.trendmicro.com/CoreTech-MARS/allexp/blob/master/PanicAndroid/stagefright/stagefright_av.patch). If apply failure, please update the patch file according to your downloaded AOSP.  
3. compile
    

  [Back Home]({{site.url}}{{site.baseurl}})