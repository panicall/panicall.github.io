---
layout: default
author: juwei lin
date: 2018-12-13 11:04:00 +0800
---

# Fuzz Android Framework TWO: AFL-Fuzz Android 9 MP4 Extractor on Linux
  本文介绍的是如何将最新的Android 9系统的Framework移植到Linux PC平台进行Fuzzing，并给出移植与Fuzzing MP4 Extractor的示例。

## Use Clang
  Fuzzing的所有模块务必使用Clang编译器，包括AFL-clang-fast， Android prebuild Clang。

### 编译AFL 
  可以参考 Reference 1这篇文章，也可以直接参考我们自己的afl-android。

### 使用Android prebuild Clang
  建议使用AOSP自带的Clang编译器，不要使用系统自带的或者官网下载的Clang，避免不必要的麻烦。
  AOSP自带的Clang也需要注意版本，请使用Android.go(Reference 2)中指定的版本，如本文使用的Clang: ~/Android/prebuilts/clang/host/linux-x86/clang-r344140b/bin/clang.  

## Develop Your Own Harness 
  StageFright是一个完整的解析解码器，我们需要Fuzz特地的解析或者解码器的话，需要自定义一个Harness，可以参考AndroidFrameworkAV，这里面包含我们自己的Harness(改造了原来的StageFright)  

## Add AFL Support For All Shared Libraries
  目前Android 9已经逐渐抛弃makefile，使用新的编译系统，所以在很多项目中mk文件被替换成了bp文件，而bp文件目前特性支持不够多，比如不支持替换编译器为afl-clang-fast等。  
    
  **2018-12-13** 方法一： Android.bp --> Android.mk   
  为了减少麻烦，我们一种解决思路是将bp换回我们熟悉的mk文件。  
  替换方法主要参考Reference 2中的Android.go，将bp语法映射回mk语法，一个成功的示例是mp4 extractor,可以参考mk和bp.  
  
  **2018/12/18** 方法二： patch soong （推荐）  
  可以强制为soong添加支持LOCAL_CC/LOCAL_CXX特性，详细请参考patch. 安装完patch后，Android.bp新加支持关键字`localCC`，如下是一个示例：  
  ```
  cc_library_shared {
    name: "libstagefright_soft_avcdec",
    vendor_available: true,
    vndk: {
        enabled: true,
    },

    localCC: "/usr/local/bin/afl-clang-fast",

    static_libs: ["libavcdec"],
    srcs: ["SoftAVCDec.cpp"],

    cflags: [
        "-Wall",
        "-Werror",
    ],

    version_script: "exports.lds",

    include_dirs: [
        "external/libavc/decoder",
        "external/libavc/common",
        "frameworks/av/media/libstagefright/include",
        "frameworks/native/include/media/openmax",
    ],

    shared_libs: [
        "libstagefright_omx",
        "libstagefright_foundation",
        "libutils",
        "liblog",
    ],

    sanitize: {
        misc_undefined: [
            "signed-integer-overflow",
        ],
        cfi: true,
        diag: {
            cfi: true,
        },
    },

    ldflags: ["-Wl,-Bsymbolic"],
    compile_multilib: "32",
}
  ```
    
  
## Compile & Fuzzing
  *编译命令*： AFL_CC=~/Android/prebuilts/clang/host/linux-x86/clang-r344140b/bin/clang AFL_CXX=~/Android/prebuilts/clang/host/linux-x86/clang-r344140b/bin/clang++ TEMPORARY_DISABLE_PATH_RESTRICTIONS=true mm -j16  
  *Fuzzing命令*： ASAN_OPTIONS='abort_on_error=1:symbolize=0' afl-fuzz -m 4096 -t 10000 -i in/ -o out/ /system/bin/stagefright -e @@

## Full Extractor & Codec List
### Extractors  

  
| Name        | Path          | Dependency Lib Name |  Dependency Lib Path |  
|:------|:--------|:-------|:--------|  
|aac|frameworks/av/media/extractors/aac|-|-|  
|amr|frameworks/av/media/extractors/amr|-|-|  
|flac|frameworks/av/media/extractors/flac|libFLAC|  
|midi|frameworks/av/media/extractors/midi|libsonivox,libmedia_midiiowrapper|  
|mkv|frameworks/av/media/extractors/mkv|libstagefright_flacdec,libwebm|  
|mp3|frameworks/av/media/extractors/mp3|libstagefright_id3|  
|mp4|frameworks/av/media/extractors/mp4|libstagefright_esds,libstagefright_id3|  
|mpeg2|frameworks/av/media/extractors/mpeg2|libstagefright_mpeg2support|  
|ogg|frameworks/av/media/extractors/ogg|libvorbisidec|  
|wav|frameworks/av/media/extractors/wav|libfifo|  

### Codecs Decoder  

  
| Name        | LibName     | Path          | Dependency Lib Name |  Dependency Lib Path |  
|:-------|:---------|:--------|:-------|:--------|   
|aacdec|libstagefright_soft_aacdec|frameworks/av/media/libstagefright/codecs/aacdec|libFraunhoferAAC|  
|amrwbdec|libstagefright_soft_amrdec|frameworks/av/media/libstagefright/codecs/amrnv/dec|libstagefright_amrnbdec,libstagefright_amrwbdec,libstagefright_amrnb_common|  
|avcdec|libstagefright_soft_avcdec|frameworks/av/media/libstagefright/codecs/avcdec|libavcdec|  
|flac|libstagefright_soft_flacdec|frameworks/av/media/libstagefright/codecs/flac/de|libstagefright_flacdec|  
|g711|libstagefright_soft_g711dec|frameworks/av/media/libstagefright/codecs/g711/dec|-|-|  
|gsm|libstagefright_soft_gsmdec|frameworks/av/media/libstagefright/codecs/gsm/dec|-|-|  
|hevcdec|libstagefright_soft_hevcdec|frameworks/av/media/libstagefright/codecs/hevcdec|libhevcdec|-|-|  
|m4v_h263|libstagefright_soft_mpeg4dec|frameworks/av/media/libstagefright/codecs/m4v_h263/dec|libstagefright_m4vh263dec|  
|mp3dec|libstagefright_soft_mp3dec|frameworks/av/media/libstagefright/codecs/mp3dec|libstagefright_mp3dec|  
|mpeg2dec|libstagefright_soft_mpeg2dec|frameworks/av/media/libstagefright/codecs/mpeg2dec|libmpeg2dec|  
|on2|libstagefright_soft_vpxdec|frameworks/av/media/libstagefright/codecs/on2/dec|libvpx|  
|opus|libstagefright_soft_opusdec|frameworks/av/media/libstagefright/codecs/opus/dec|libopus|  
|raw|libstagefright_soft_rawdec|frameworks/av/media/libstagefright/codecs/raw|-|-|  
|vorbis|libstagefright_soft_vorbisdec|frameworks/av/media/libstagefright/codecs/vorbis/dec|libvorbisidec|  
|xaacdec|libstagefright_soft_xaacdec|frameworks/av/media/libstagefright/codecs/xaacdec|libxaacdec|  



## Reference
1. [在Linux上使用AFL对Stagefright进行模糊测试](http://ele7enxxh.com/Use-AFL-For-Stagefright-Fuzzing-On-Linux.html)  
2. Android/build/soong/androidmk/cmd/androidmk/android.go

