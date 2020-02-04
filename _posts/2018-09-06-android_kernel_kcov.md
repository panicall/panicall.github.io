---
layout: default
author: juwei lin
date: 2018-09-06 13:00:00 +0800
---

## What is KCOV?
[SanitizerCoverage](https://clang.llvm.org/docs/SanitizerCoverage.html)  

> LLVM has a simple code coverage instrumentation built in (SanitizerCoverage). It inserts calls to user-defined functions on function-, basic-block-, and edge- levels. Default implementations of those callbacks are provided and implement simple coverage reporting and visualization.   
> Kcov was developed to allow for coverage-guided fuzz testing in the kernel.  

We can enable KCOV to trace PCs and Data. In the following article, I will introduce tracing PCs.  

## Tracing PCs
> With -fsanitize-coverage=trace-pc the compiler will insert __sanitizer_cov_trace_pc() on every edge. With an additional ...=trace-pc,indirect-calls flag __sanitizer_cov_trace_pc_indirect(void *callee) will be inserted on every indirect call. These callbacks are not implemented in the Sanitizer run-time and should be defined by the user. This mechanism is used for fuzzing the Linux kernel (https://github.com/google/syzkaller).  
  

## KCOV(Tracing PCs) in Android Kernel
### Build a kernel with KCOV ON
Skip building kernel with KCOV ON, please refer to [KASAN in Anroid Kernel](./posts/2018_09_06_android_kernel_kasan.html).  
vmlinux can be found [here](https://adc.github.trendmicro.com/CoreTech-MARS/allexp/tree/master/resource/bin/android_kernel/goldfish_4.9_dev/x86_64/ksan_kcov)
### KCOV(Tracing PCs) in Android source code
```C
/*
 * Entry point from instrumented code.
 * This is called once per basic-block/edge.
 */
void notrace __sanitizer_cov_trace_pc(void)
{
	struct task_struct *t;
	unsigned long *area;
	unsigned long ip = canonicalize_ip(_RET_IP_);
	unsigned long pos;

	t = current;
	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
		return;

	area = t->kcov_area;
	/* The first 64-bit word is the number of subsequent PCs. */
	pos = READ_ONCE(area[0]) + 1;
	if (likely(pos < t->kcov_size)) {
		area[pos] = ip;
		WRITE_ONCE(area[0], pos);
	}
}
EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
```

### KCOV(Tracing PCs) in Android bin
![kcov_bin]({{site.url}}{{site.baseurl}}/res/kcov.png)  


  [Back Home]({{site.url}}{{site.baseurl}})
