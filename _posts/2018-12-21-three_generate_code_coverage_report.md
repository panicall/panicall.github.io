---
layout: default
author: juwei lin
date: 2018-12-21 13:54:00 +0800
---

# Fuzz Android Framework THREE: Generate Code Coverage Report
We use AFL to fuzz Android framework, we need to generate the code coverage report for review. There are many methods we can use. In this article we introduce several methods for your reference.  

## For UserMode Closed Source Project
We mainly use DBI technique to get code coverage for closed source binary.
* [DynamoRIO](https://github.com/DynamoRIO/dynamorio/releases)
* [Pin](https://github.com/gaasedelen/lighthouse/tree/master/coverage/pin)
* [Frida](https://github.com/gaasedelen/lighthouse/tree/master/coverage/frida)
  
### DynamoRIO
Usage: dynamoriodir\bin32\drrun.exe -t drcov — harness.exe testcase  

Example:  
1. Use DynamoRIO to DBI the target
```
mexp@staging-mexp226:/data$ DynamoRIO/DynamoRIO-x86_64-Linux-7.0.17880-0/bin64/drrun -t drcov -- test/test 5
hello world
you get the secret!
idvalue: 5
```
it generates a result file named `drcov.test.15822.0000.proc.log`.  

2. Use lighthouse to show the result
[lighthouse](https://github.com/gaasedelen/lighthouse) can render the result inside IDA or Binary Ninja.
![test_dynamorio_1]({{site.url}}{{site.baseurl}}/res/test_dynamorio_1.png) 
![test_dynamorio_2]({{site.url}}{{site.baseurl}}/res/test_dynamorio_2.png) 

### Pin
Install Pin & CodeCoverage under the [instructions](https://github.com/gaasedelen/lighthouse/tree/master/coverage/pin).

Example:
1. Use Pin to DBI the target
```
mexp@staging-mexp226:/data$ ./Pin/lighthouse/pin-3.7-97619-g0d0c92f4f-gcc-linux/pin -t Pin/lighthouse/lighthouse-master/coverage/pin/obj-intel64/CodeCoverage.so -- ./test/test 5
CodeCoverage tool by Agustin Gianni (agustingianni@gmail.com)
Logging code coverage information to: trace.log
Loaded image: 0x400000:0x406417 -> test
Loaded image: 0x7f6f2b554000:0x7f6f2b57ac23 -> ld-linux-x86-64.so.2
Loaded image: 0x7ffc641ee000:0x7ffc641ef00a -> [vdso]
Loaded image: 0x7f6f17aa3000:0x7f6f17e93adf -> libc.so.6
hello world
you get the secret!
idvalue: 5
mexp@staging-mexp226:/data$
```
it generates a result file named `trace.log`.

2. Use lighthouse to show the result
lighthouse can render trace.log directly.


## For UserMode Open Source Project
CLANG and GCC both support instrumentation. This article talks about clang and there are different ways to get code coverage by using clang instrumentation.
* [source based code coverage](https://clang.llvm.org/docs/SourceBasedCodeCoverage.html)
* [sanitizer coverage](https://clang.llvm.org/docs/SanitizerCoverage.html)
* gcov - A GCC-compatible coverage implementation which operates on DebugInfo. This is enabled by -ftest-coverage or --coverage.
  
### Source Based Code Coverage
This is the method we use in our fuzzing project.  
  
The code coverage workflow consists of three main steps:
* Compiling with coverage enabled.
* Running the instrumented program.
* Creating coverage reports.
  
Example:  
#### 1. Compiling with coverage enabled  
1.1 pass `-fprofile-instr-generate -fcoverage-mapping to the compiler` to `cflags` and `ldflags` in Android.bp of avcdec module(`libstagefright_soft_avcdec` and `libavc`)  
```
cc_library_shared {
    name: "libstagefright_soft_avcdec",
    vendor_available: true,
    vndk: {
        enabled: true,
    },

    static_libs: ["libavcdec"],
    srcs: ["SoftAVCDec.cpp"],

    cflags: [
        "-Wall",
        "-Werror",
        "-fprofile-instr-generate",
        "-fcoverage-mapping",
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

    ldflags: ["-Wl,-Bsymbolic","-fprofile-instr-generate","-fcoverage-mapping"],
    compile_multilib: "32",
}
```
1.2 compile avcdec
```
source ~/Android/build/envsetup.sh
lunch 
27
mm -j16
```

#### 2. Running the instrumented program
```
/system/bin/stagefright -m 1 -c /data/afl/meta_in/setup_welcome_video.mp4 /data/afl/in/raw1.mp4
```
it generates the file `default.profraw`  

#### 3. Creating coverage reports
Raw profiles have to be indexed before they can be used to generate coverage reports. This is done using the “merge” tool in llvm-profdata (which can combine multiple raw profiles and index them at the same time):
```
% llvm-profdata merge -sparse default.profraw -o default.profdata
```
There are multiple different ways to render coverage reports.  
One is to use `llvm-cov report` to give report at file level:
```
mexp@staging-mexp226:~/Android$ llvm-cov report /home/mexp/Android/out/target/product/generic_x86/symbols/system/lib/libstagefright_soft_avcdec.so -instr-profile=default.profdata
Filename                                                                                                                                                                  Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
external/libavc/common/ih264_buf_mgr.c                                                                                                                                        167               107    35.93%          15                 8    46.67%         273               145    46.89%
external/libavc/common/ih264_chroma_intra_pred_filters.c                                                                                                                       99                49    50.51%           4                 3    25.00%         246                97    60.57%
external/libavc/common/ih264_deblk_edge_filters.c                                                                                                                            1039              1039     0.00%          18                18     0.00%        1286              1286     0.00%
external/libavc/common/ih264_disp_mgr.c                                                                                                                                        29                 2    93.10%           3                 0   100.00%          61                 4    93.44%
external/libavc/common/ih264_ihadamard_scaling.c                                                                                                                               29                29     0.00%           2                 2     0.00%         116               116     0.00%
external/libavc/common/ih264_inter_pred_filters.c                                                                                                                             202               202     0.00%          12                12     0.00%         415               415     0.00%
external/libavc/common/ih264_iquant_itrans_recon.c                                                                                                                            290               290     0.00%           6                 6     0.00%         569               569     0.00%
external/libavc/common/ih264_luma_intra_pred_filters.c                                                                                                                        368               368     0.00%          23                23     0.00%         945               945     0.00%
external/libavc/common/ih264_padding.c                                                                                                                                         30                22    26.67%           6                 4    33.33%          80                64    20.00%
external/libavc/common/ih264_weighted_pred.c                                                                                                                                  114               114     0.00%           6                 6     0.00%         185               185     0.00%
external/libavc/common/ithread.c                                                                                                                                               24                12    50.00%          20                11    45.00%          75                36    52.00%
external/libavc/common/x86/ih264_chroma_intra_pred_filters_ssse3.c                                                                                                             13                 0   100.00%           3                 0   100.00%         239                 0   100.00%
external/libavc/common/x86/ih264_deblk_chroma_ssse3.c                                                                                                                           6                 2    66.67%           6                 2    66.67%         761               202    73.46%
external/libavc/common/x86/ih264_deblk_luma_ssse3.c                                                                                                                            16                 2    87.50%           6                 2    66.67%        1731               527    69.56%
external/libavc/common/x86/ih264_ihadamard_scaling_sse42.c                                                                                                                      7                 7     0.00%           2                 2     0.00%         146               146     0.00%
external/libavc/common/x86/ih264_inter_pred_filters_ssse3.c                                                                                                                   215               215     0.00%          10                10     0.00%        3833              3833     0.00%
external/libavc/common/x86/ih264_iquant_itrans_recon_dc_ssse3.c
```
Another way is to generate the report at source code function level:  
```
mexp@staging-mexp226:~/Android$ llvm-cov show /home/mexp/Android/out/target/product/generic_x86/symbols/system/lib/libstagefright_soft_avcdec.so -instr-profile=default.profdata --format html > /data/coverage.html
```
it generates the [html](https://adc.github.trendmicro.com/CoreTech-MARS/allexp/blob/master/docs/res/coverage.html) for your review at function level.  
![coverage_html]({{site.url}}{{site.baseurl}}/res/coverage_html.png)  

#### 4. Exporting coverage data  
Coverage data can be exported into JSON using the llvm-cov export sub-command. There is a comprehensive reference which defines the structure of the exported data at a high level in the llvm-cov source code.  
  
### Sanitizer Coverage
_all the following contents are from [here](https://clang.llvm.org/docs/SanitizerCoverage.html)._  

The sanitizer run-time (AddressSanitizer, MemorySanitizer, etc) provide a default implementations of some of the coverage callbacks. You may use this implementation to dump the coverage on disk at the process exit.  
Example:  
```
% cat -n cov.cc
     1  #include <stdio.h>
     2  __attribute__((noinline))
     3  void foo() { printf("foo\n"); }
     4
     5  int main(int argc, char **argv) {
     6    if (argc == 2)
     7      foo();
     8    printf("main\n");
     9  }
% clang++ -g cov.cc -fsanitize=address -fsanitize-coverage=trace-pc-guard
% ASAN_OPTIONS=coverage=1 ./a.out; wc -c *.sancov
main
SanitizerCoverage: ./a.out.7312.sancov 2 PCs written
24 a.out.7312.sancov
% ASAN_OPTIONS=coverage=1 ./a.out foo ; wc -c *.sancov
foo
main
SanitizerCoverage: ./a.out.7316.sancov 3 PCs written
24 a.out.7312.sancov
32 a.out.7316.sancov
```
Every time you run an executable instrumented with SanitizerCoverage one *.sancov file is created during the process shutdown. If the executable is dynamically linked against instrumented DSOs, one *.sancov file will be also created for every DSO.  
  
The format of *.sancov files is very simple: the first 8 bytes is the magic, one of 0xC0BFFFFFFFFFFF64 and 0xC0BFFFFFFFFFFF32. The last byte of the magic defines the size of the following offsets. The rest of the data is the offsets in the corresponding binary/DSO that were executed during the run.  
  
An simple sancov tool is provided to process coverage files. The tool is part of LLVM project and is currently supported only on Linux. It can handle symbolization tasks autonomously without any extra support from the environment. You need to pass .sancov files (named <module_name>.<pid>.sancov and paths to all corresponding binary elf files. Sancov matches these files using module names and binaries file names.
```
USAGE: sancov [options] <action> (<binary file>|<.sancov file>)...

Action (required)
  -print                    - Print coverage addresses
  -covered-functions        - Print all covered functions.
  -not-covered-functions    - Print all not covered functions.
  -symbolize                - Symbolizes the report.

Options
  -blacklist=<string>         - Blacklist file (sanitizer blacklist format).
  -demangle                   - Print demangled function name.
  -strip_path_prefix=<string> - Strip this prefix from file paths in reports
```

### Gcov
[afl-cov](https://github.com/mrash/afl-cov) is based on gcov. 

Example:
#### 1. Use Gcc or Clang to compile the target with two flags: `-fprofile-arcs -ftest-coverage`  
```
mexp@staging-mexp226:/data/test$ clang -fprofile-arcs -ftest-coverage -o test test.c
test.c:22:27: warning: implicit declaration of function 'atoi' is invalid in C99 [-Wimplicit-function-declaration]
                idvalue = atoi("5");
                          ^
1 warning generated.
mexp@staging-mexp226:/data/test$
```
it generates binary `test` and an extra file named `test.gcno`.  
```
mexp@staging-mexp226:/data/test$ ls
test  test.c  test.gcno
```
#### 2. Run the target binary  
```
mexp@staging-mexp226:/data/test$ ./test 5
hello world
you get the secret!
idvalue: 5
```
it generates two more files: `test.gcda` and `default.profraw`.  
```
mexp@staging-mexp226:/data/test$ ls
default.profraw  test  test.c  test.gcda  test.gcno
```

#### 3. Collect code coverage  
Read the *.gcda with llvm-cov
```
mexp@staging-mexp226:/data/test$ llvm-cov gcov -f -b test.gcda
```
it then generates test.c.gcov for reivew.
```
mexp@staging-mexp226:/data/test$ ls
default.profraw  test  test.c  test.c.gcov  test.gcda  test.gcno
```
the content of test.c.gcov:
```
        -:    0:Source:test.c
        -:    0:Graph:test.gcno
        -:    0:Data:test.gcda
        -:    0:Runs:1
        -:    0:Programs:1
        -:    1:#include <stdio.h>
        -:    2:
        -:    3://void _start() {
        -:    4://      printf("hello world\n");
        -:    5://}
        -:    6:
function main called 1 returned 100% blocks executed 75%
        -:    7:int main(int argc, char* argv[]) {
        -:    8:        char id;
        1:    9:        int idvalue = 0;
        -:   10:
        1:   11:        printf("hello world\n");
        -:   12:
        1:   13:        if (argc != 2) {
branch  0 taken 0%
branch  1 taken 100%
    #####:   14:                printf("failure request\n");
    #####:   15:                return 0;
        -:   16:        }
        -:   17:
        1:   18:        id = argv[1][0];
        -:   19:
        1:   20:        if (id == '5') {
branch  0 taken 100%
branch  1 taken 0%
        1:   21:                printf("you get the secret!\n");
        1:   22:                idvalue = atoi("5");
        1:   23:                printf("idvalue: %d\n", idvalue);
        1:   24:        }
        -:   25:        else {
    #####:   26:                printf("you didn't get the secret\n");
        -:   27:        }
        -:   28:
        1:   29:        return 0;
        1:   30:}
```

#### 4. Use lcov and genhtml to generate the html file for review
[skip](http://logan.tw/posts/2015/04/28/check-code-coverage-with-clang-and-lcov/).

  [Back Home]({{site.url}}{{site.baseurl}})