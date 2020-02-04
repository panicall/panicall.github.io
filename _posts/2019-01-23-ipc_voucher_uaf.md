---
layout: default
author: juwei lin
date: 2018-01-23 16:47:00 +0800
---

# IPC Voucher UaF Remote Jailbreak Stage 2

**Author: Qixun Zhao(@S0rryMybad) of Qihoo 360 Vulcan Team**

在今年11月份的天府杯比赛中,我演示了iPhoneX 最新iOS系统的远程越狱,这篇文章讲述的是这个exploit chain的stage 2.这里我用到的是一个沙盒内可以直接到达的内核漏洞(I name it Chaos),所以在取得Safari的RCE以后,我们可以直接从Safari沙盒内触发这个漏洞,最终达到远程越狱.

在这里文章中,我将会放出Chaos的PoC,并且会详细讲解(面向初学者)如何在A12上取得tfp0的exploit细节,但是我不会放出exploit的代码,如果你想要越狱,这需要你自己去完成exploit的代码或者等待越狱社区去开发.同时,我不会提及post exploit的利用细节,请把这个任务交给越狱社区.

这是在比赛前夕录取的在iPhoneX最新系统上利用Chaos进行rjb DEMO:
http://v.youku.com/v_show/id_XNDAyNjM1Mjk0OA==.html

## 0x0 基础知识
如果你不是初学者或者对这部分不感兴趣,请直接跳过.

### 0x01 关于port的概念
在苹果的内核中,port是一个十分重要的概念,并且易学难精(特别是它的引用计数关系),如果已经完全弄懂了port到底是怎样的东西,你已经是iOS内核中的佼佼者.  
  
简单来说,port是一个单向传输通道,在内核中对应的内核对象是ipc_port,只能有一个接收方,但是可以有多个发送方.请记住是单向,不是双向,因为只能有一个接收方,如果你想发送消息给一个port,前提你需要有这个port的send right,这些right的信息保存在进程相关的ipc entry table中,所以right的信息是每个进程独立的,即使它们表示的port是同一个.正因为这个原因,所以port的权限可以在每个进程隔离.但是需要注意的是ipc_port这个内核对象是共享的,如果表示的内核port是同一个,所有的ipc entry都是指向同一个port,这也方便了port进程间的共享.  
  
port有两种重要的作用,第一种是用于进程间通讯,第二种是用于表示一个内核对象,相当于windows中的句柄.第二种是第一种的特殊情况,也就是当port的接收方是ipc_space_kernel的时候.如果你想对一个内核对象进行操作,前提你需要有这个内核对象对应的port的send right.  
  
所谓的tfp0就是task for pid 0, pid 0对应的是内核进程, 因为task也是一个内核对象,所以它可以用port来表示,如果取得了pid 0的task port的send right, 就可以利用这个task port调用各种进程的内核API,通过这些API可以达到内核任意地址读写.  

### 0x02 关于MIG
在苹果的代码中,有一种称为MIG的代码,这是根据defs文件自动生成的代码,里面一般会做一些内核间对象的转换(例如port到内核对象)以及对象引用计数的管理,然后调用真正的内核函数.如果kernel代码编写人员不熟悉defs的含义或者MIG对对象引用计数的管理,在这个MIG包裹的真正内核API中不适当地管理内核对象的引用计数,是很容易产生引用计数的泄露或者double free.  

## 0x1 漏洞发现过程与细节
在一开始的时候,我看到这样一段代码,注意这不是最终的漏洞:
![semaphore_destroy](/images/res/semaphore_destroy.png)  
我们可以发现,在semaphore非空的时候,每一个路径都调用了semaphore_dereference,除了!=task那个路径,所以直觉告诉我,无论MIG的代码是怎样的,这里面肯定会有一个路径会发生引用计数的泄露.经过浏览MIG的函数后,我发现确实!=task的路径发生了引用计数的泄露,这个在iOS12之前是可以利用的,并且在沙箱内可以出发,只不过需要很久的时间去触发引用计数的溢出,意义不大.并且在最新版已经修复.  
  
但是,如果你是一个老练的漏洞挖掘人员,你应该有敏锐的触觉第一时间想到,这部分的代码肯定是缺少review并且质量不怎么好,毕竟这里可是沙盒内能直达的代码啊,也意味着内核编写人员可能并不熟悉MIG代码的生成规则.这个信息比找到上面那个鸡肋的漏洞更加重要,于是我开始找这些MIG相关的内核函数,当然是沙盒直达的.这也启示了我以后挖掘漏洞的一些方法.  
![sorrymybad_twitter](/images/res/sorrymybad_twitter.png)  
接着,我在相关的代码中看到一个平平无奇的内核函数task_swap_mach_voucher,也就是漏洞的核心所在:  
![task_swap_voucher](/images/res/task_swap_voucher.png)  

如果不配合MIG函数看, 肯定是看不出这个平平无奇的函数所存在的问题,因此我们看看对应的MIG函数:  
![task_swap_voucher_mig](/images/res/task_swap_voucher_mig.png)  
  
其中convert_port_to_voucher是会把对应的ipc_voucher 引用计数加一, ipc_voucher_release和convert_voucher_to_port会把引用计数减一.看起来没有任何问题,无论new_voucher还是old_voucher都是先加一再减一,并且没有任何赋值,所以引用计数也不需要变化.  
  
但是我们再来回顾那个平平无奇的函数,里面把new_voucher赋值到old_voucher了!!!!!这意味着,当task_swap_mach_voucher调用出来后,new_voucher是等于old_voucher,换句话说,new_voucher会被double free,同时old_voucher不会有free.发生引用计数泄露,所以这里一共有两个问题.当然double free的利用价值更加大,不需要等漫长的时间触发引用计数溢出,所以最终我们得到的PoC如下:  
![main_poc](/images/res/main_poc.png)  

首先通过thread_set_mach_voucher设置一个dangling pointer,然后通过漏洞释放ipc voucher对象,然后通过thread_get_mach_voucher触发crash.接下来就是如何在A12上利用.  

## 0x2 get the tfp0 on A12
UaF的漏洞通常是要fake对应的漏洞对象,所以在利用这个漏洞之前,我们首先要搞清楚我们UaF的对象ipc_voucher到底是怎样的数据结构:  
![ipc_voucher](/images/res/ipc_voucher.png)  
  
好消息是ipc_voucher里面存在一个ipc_port_t iv_port,并且这个port是可以通过thread_get_mach_voucher => convert_voucher_to_port 传回用户态,意味着我们可以通过fake port的方法直接构造一个tfp0.关于fake port的利用有一篇写得十分好的文章(via@s1guza ),强烈推荐阅读: https://siguza.github.io/v0rtex/. 我的利用中参考这篇文章和代码很多.  
  
坏消息是我们都知道ipc_voucher是一个内核对象,意味着这个伪造的fake port我们没有receive right, 这对于tfp0没有任何影响,因为只需要有send right就可以完全控制这个内核对象,但是对利用过程有一定的影响.  
  

### 0x21 Zone GC
在iOS的内核里, 不同的内核对象隔离在不同的zone, 这意味着即使ipc voucher对象释放了,这个对象不是真正的释放,只是放到对应的zone的free list,我们也只可能重新分配一个ipc voucher去填充.但是一般的UaF的漏洞我们都是需要转换成Type Confusion去利用,也就是我们需要分配一个不同的内核对象去填充这个释放的ipc voucher内存区域,在这里我们需要手动触发内核的zone gc, 把对应的page释放掉.  
  
在这里我用到的方法是分配很多的ipc_voucher对象,这里起码得超过一个page的大小,然后全部释放掉.因为zone gc的最小单位是一个page, 如果一个page里面不是全部ipc_voucher被释放,那么在zone gc的时候并不会释放这个page(详情参考MacOS X and iOS Internals:To the Apple’s Core Page 427 中文版):  
![ipc_voucher_zone_gc](/images/res/ipc_voucher_zone_gc.png)  
  
在释放完毕后,我们需要释放zone gc,把对应的page释放回操作系统管理,触发的方法在ian beer以往的利用中已经有介绍过,利用分配大量的port并且发送消息即可:  
![release_zone_gc](/images/res/release_zone_gc.png)  
  
这里有一个坑就是我们最好通过usleep稍微等待一些时间,因为zone gc需要一些时间,因为这个坑我调试的时候就发生了很诡异的bug:在调试器里运行得很好,但是一脱离调试器就panic.  

### 0x22 leak a receive port addr
把对应的内存释放后,我们开始考虑应该填充什么东西.首先第一步我们肯定是需要泄漏一些内核的信息,例如一些堆地址,因为在fake ipc_voucher和port的时候需要用到,后续我们还要在这个内存区域填充任意数据去fake.所以第一时间我们想到的是OSString,因为利用OSString我们可以完全控制内核的数据,并且可以通过一些API把OSString的数据读回来,从而泄漏内核的信息.  
  
关于OSString的分配我们可以用IOSurfaceRootUserClient的接口IOSURFACE_GET_VALUE和IOSURFACE_SET_VALUE.  
  
第一步我们可以泄漏的东西是一个port的地址,具体我们看代码convert voucher to port:  
![convert_voucher_to_port](/images/res/convert_voucher_to_port.png)  
  
如果iv_port为空,则内核会分配一个新的port,并且放在iv_port的位置.所以在第一步重新分配OSString去fake ipc_voucher的关键就在于令iv_port这个offset为空,在分配port完成后,通过API把OSString读回来,就可以得到刚分配的一个port的地址.  
  
还有很重要的一点是offset问题,如果分配的OSString的开始位置不能刚好对应ipc_voucher的开始位置,我们伪造的一切数据都会错误.这里因为在iPhone XS Max中(A12)一个page的大小是0x4000,而zone的分配是以page为单位的,也就是说第一个ipc_voucher必定是page对齐的,所以我们分配的OSString只需要page对齐即可以保证和ipc_voucher对齐.(这里可能有点难理解,原谅我的表达能力),分配代码如下:  
  
![ipc_voucher_1](/images/res/ipc_voucher_1.png)  
这里的padding我们暂时不用管是什么,后续会用到.因为port为0x0, 所以在port后续会赋值一个port的真实地址,然后通过查找找出port的地址和占据了对应内存的OSString index:  
![ipc_voucher_2](/images/res/ipc_voucher_2.png)  
我们之前提到了这个port是没有send right的,后续我们利用中需要用到receive right去泄漏kernel的slide,所以这里我用了一个trick,在它附近分配大量的带有receive right的port,最后我们可以用这个地址减去sizeof(ipc_port_t)即可得到一个receive right port的地址.  
![ipc_voucher_3](/images/res/ipc_voucher_3.png)  
![ipc_voucher_4](/images/res/ipc_voucher_4.png)  

### 0x23 Fake a port
因为SMAP的关系,我们需要在内核地址中伪造port,这里我们需要得到一个我们可控的内核地址,也就是上面分配的那么多的OSString的其中一个即可,通过heap spray大量分配内存可以令这个地址更加容易猜测.  
  
一开始我打算用泄漏的port地址去计算相关的偏移得到这个地址,但是后来我发现iOS中的堆地址随机化比较弱,所以这里我用了一个固定的地址:  
![ipc_voucher_5](/images/res/ipc_voucher_5.png)  
然后我们重新分配上面提到的OSString,重新伪造ipc_voucher,令它的port指向我们的可控地址,还记得我们记录下了对应的OSString的idx了吗?通过它我们可以很快定位出需要reallocate的OSString:  
![ipc_voucher_6](/images/res/ipc_voucher_6.png)  

这里的第三个参数就是需要伪造的port的地址,我们看到这里有一个magic offset 0x8,在Fake Voucher开始位置再减去magic offset，也指向在上文我们提到的padding第二个域:  
![ipc_voucher_7](/images/res/ipc_voucher_7.png)  
  
在这里我把fake voucher和fake port的内存区域重叠起来了,在padding+0x8的地方其实是fake port的开始地址,再往后会返回到hash域，通过这样的布局刚好可以满足fake voucher和fake port的要求而且不panic.这里重叠起来实属无奈之举,因为我们只有一次重分配的机会,如果重分配两次,第一次分配的OSString 用来fake voucher,第二次用来fake port,则我们猜测的地址有一半可能是指向fake voucher,现在这样只有一种可能,就是指向fake port.  

### 0x24 leak the idx OSString of fake port  
由于后期需要多次重分配fake port内存区域的数据,所以需要找到fake port对应的OSString的index:  
![ipc_voucher_8](/images/res/ipc_voucher_8.png)  
  
通过调用thread_get_mach_voucher=>convert_voucher_to_port, 我们可以得到两个需要的东西.第一是OSString的index,因为convert_voucher_to_port会修改fake port区域的reference,通过这个不同可以找出index:  
![ipc_voucher_9](/images/res/ipc_voucher_9.png)  
第二个得到的是指向我们可控地址的用户态port, 也就是上图中的fake_port_to_addr_control,通过它和修改fake port的数据,我们可以做很多事情.  

### 0x25 任意内存地址读
通过在fake port中伪造一个task port, 然后通过调用pid_for_task(关于这个利用技巧网上已有大量讨论,这里不再解释), 我们可以任意地址读,每一次是32位,但是弊端就在于每一次读取我们都要重新分配OSString,因为我们需要修改fake port中需要读取的内存地址.因为我们知道对应的OSString index,我们不需要全部OSString重新分配:  
![ipc_voucher_10](/images/res/ipc_voucher_10.png)  
这里我不是单单只重分配对应的index,是设置了一个range 0x50,也就是把这个index前后0x50个OSString也重新分配,令我吃惊的是,这个重分配出奇的稳定,原本我会觉得这个exploit会挺不稳定.  
  
在上文我们已经泄漏了一个带有receive right的port 地址,利用这个地址加任意地址读,我们可以最后得到kernel slide,关于这部分内容以及接下来的网上已有讨论的我不再详述,还是推荐看这篇文章https://siguza.github.io/v0rtex/  
![ipc_voucher_11](/images/res/ipc_voucher_11.png)  

### 0x26 fake a map port
现在的我们每一次操作fake port都要重新分配OSString,这对于利用十分不友好,在得到了kernel的slide,我们下一步应该立刻把fake_port_to_addr_control 对应的内核地址remap到我们进程的用户态,这样以后每一次修改fake port的数据就可以直接在用户态修改,不需要通过重分配OSString:  
![ipc_voucher_12](/images/res/ipc_voucher_12.png)  
通过remap后,用户态对应地址和内核态对应地址共享一个物理内存区域,这样通过修改用户态的地址即可达到修改内核态对应地址的数据的目的(除非是COW)  

### 0x27 Fake TFP0
由于在convert_port_to_task中会检测port的ip_kobject,也就是task_t的地址是否等于kernel_task,所以我们不能直接把读取出来的kernel_task地址赋值到fake port的ip_kobject中,而需要它先memcpy到另外一个内核地址,然后再赋值.  
  
这里我分开两步骤,第一用一个真实的内核对象port去初始化fake port的所有数据,因为tfp0和所有内核对象的port都是共享一个receiver ipc_space_kernel,这里我用了一个IOSurefaceRootUserClient的port去初始化.如果不这样做在用tfp0调用内核API的时候会出错,因为很多属性值还没有初始化,例如ip_messages.  
![ipc_voucher_13](/images/res/ipc_voucher_13.png)  
  
接下来把原生的kernel task地址copy到另外一个内核地址,并且修改tfp0 port中一些与IOSurefaceRootUserClient port不同的部分:  
![ipc_voucher_14](/images/res/ipc_voucher_14.png)  
  
最后一步,重新分配fake voucher中的port地址,指向我们最新fake tfp0的地址,然后通过thread_get_mach_voucher返回到用户态,最终得到tfp0: 
![ipc_voucher_15](/images/res/ipc_voucher_15.png)  

## 0x3 Cleaning the stuff
因为我们在程序结束的时候，还有一个danging Pointer在thread mach voucher中指向我们的danging Pointer，而danging Pointer是指向我们OSString分配的内存，这部分内存在IOSurfaceRootUserClient释放的时候进行释放的，也就是进程结束的时候。除此之外，还有众多我们伪造的port，都是指向OSString分配的内存，所以都要在进程结束前一并回收.  
![ipc_voucher_16](/images/res/ipc_voucher_16.png)  
最后，包括我们最终生成的tfp0，也是需要进行释放的，所以如果想要保持tfp0的持久性，最好在post exploit阶段重新自己构造一个新的tfp0.至此tfp0的利用已经结束,关于后续的post exploit, 根目录读写,签名bypass等等这里不会提及.  

## 0x4 总结
我们都知道，在A12中引入了PAC的mitigation，很多人都觉得这是UaF甚至是越狱的终点.事实证明，UaF的洞还是可以在PAC的环境下利用，这需要看具体的情况，因为PAC只是针对间接调用控制pc寄存器这一方面。我们可以看到，在取得tfp0的整个过程中,我们不需要控制pc寄存器,这是因为我们释放的对象ipc_voucher中存在一个port的属性值.UaF漏洞的利用很大程度上依赖这个释放的对象的数据结构以及这些数据结构怎么去使用,因为最终我们要转换成type confusion.

本文链接：http://blogs.360.cn/post/IPC Voucher UaF Remote Jailbreak Stage 2.html  
