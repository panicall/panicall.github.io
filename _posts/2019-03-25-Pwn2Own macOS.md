# Pwn2Own macOS

​	本文介绍了如何使用两个漏洞（CVE-2018-4413和CVE-2018-4425）实现macOS（10.14及其以前的版本） root，主要使用的exploit技巧来自Google Project Zero的Ian Beer在async_wake_ios中展示的ipc port exploit技巧。所以接下来的内容主要是:

 * 漏洞介绍
 * root介绍

## 一、漏洞介绍

### CVE-2018-4413

​	这是一个因堆内存未初始化造成内容泄漏的漏洞，在iOS 12.1以及macOS 10.14.1中修复了，这个漏洞可以用来泄漏ipc_port内核对象的地址。接下来我们来看看这个漏洞的详细信息。

​	这个漏洞发生在sysctl_procargsx函数中：![image-20190324221646704](/images/PwnMac/image-20190324221646704.png)

​	在位置(a)处，p->p_argslen的值一般是0x300左右，所以当我们传入的参数arg_size （可控参数）为0x200时，round_page函数不会被调用。紧接着这个函数调用kmem_alloc分配了一块内核内存，记为copy_start，大小是round_page(arg_size)，也就是一个页面大小，注意分配出来的内存没有清零。同时记录这块内存的结束位置为copy_end。分配成功后，该函数又调用了vm_map_copyin把进程的启动参数信息arg_addr拷贝到了一个临时变量tmp中。

![image-20190324222043472](/Users/juwei_lin/Library/Application Support/typora-user-images/image-20190324222043472.png)

​	接下来，在位置(b)处，调用了vm_map_copy_overwrite将tmp中的内容又拷贝到了新分配的copy_start处。接着进入到位置(c)处，data指向上文中分配的那块一个页面内存的倒数0x200处。继续执行到位置(d)处，将data指向的0x200字节大小内容拷贝回用户态给调用者。问题就在这里，因为data处指向的是分配内存的倒数0x200处，由于该内存没有被清零，此时data指向的是未初始化的堆内存数据。

​	整个问题的描述如下图所示，该函数的原意是将copy_start处的0x200内容拷贝回去，但因为出现了逻辑漏洞，实际将未初始化的最后0x200内容拷贝回去了。

![image-20190324223735800](/Users/juwei_lin/Library/Application Support/typora-user-images/image-20190324223735800.png)

​	这个漏洞可以用来泄漏ipc_port内核对象的地址值。方法是使用类型为MACH_MSG_OOL_PORTS_DESCRIPTOR的mach message来实现，具体内容请参考Ian Beer的async_wake_ios源码。

​	苹果修复这个漏洞使用的方法也很简单，使用bzero函数在内存分配后清零即可，如下所示。

![image-20190324224300022](/Users/juwei_lin/Library/Application Support/typora-user-images/image-20190324224300022.png)



### CVE-2018-4425

​	这是一个NECP类型混淆的漏洞，在macOS 10.14中修复，这个漏洞可以用来释放任意内核地址。

​	在介绍这个漏洞之前，我们先来看一下NECP的攻击界面。NECP中有两个非常直观的攻击界面，一个是necp client action系列，还有一个是necp session action系列。

​	首先来看necp client action系列：

​	![image-20190324224727568](/Users/juwei_lin/Library/Application Support/typora-user-images/image-20190324224727568.png)

​	首先用户需要调用necp_open函数获得一个句柄，然后就可以使用这个句柄来调用necp_client_action，necp_client_action实际是一个分发函数，根据传入的参数分发到不同的服务函数。

​	necp_open函数会创建一个necp_fd_data类型的内核对象，如下所示：

![image-20190324225113831](/Users/juwei_lin/Library/Application Support/typora-user-images/image-20190324225113831.png)

​	necp_open创建完necp_fd_data这个内核对象后会返回一个句柄给用户，用户接下来就可以使用这个句柄来调用necp_client_action了。如下所示：

![image-20190324225315028](/Users/juwei_lin/Library/Application Support/typora-user-images/image-20190324225315028.png)	根据用户传入的句柄uap->necp_fd，necp_client_action通过调用necp_find_fd_data函数查询到在necp_open中创建的necp_fd_data内核对象。我们来看看necp_find_fd_data函数是如何工作的：

![image-20190324225602516](/Users/juwei_lin/Library/Application Support/typora-user-images/image-20190324225602516.png)

​	可以看到，necp_find_fd_data函数首先调用fp_lookup查询句柄fd对应的fp，接着验证fp记录的fo_type值是否为DTYPE_NETPOLICY，如果是，则验证通过，返回fg_data为necp_fd_data。

​	我们再来看看另一个攻击界面necp session action，这个攻击界面和necp client action非常相似：

![image-20190324230046925](/Users/juwei_lin/Library/Application Support/typora-user-images/image-20190324230046925.png)

​	这里简单描述一下，这个攻击界面的工作流程主要如下：

​	1. 用户调用necp_session_open获得一个句柄，该句柄指向内核对象necp_session。

​	2. 用户使用返回的句柄调用necp_session_action函数。  

​	那么漏洞到底出在哪里呢，我们来看看necp_session_action函数：

![image-20190324230355366](/Users/juwei_lin/Library/Application Support/typora-user-images/image-20190324230355366.png)

​	necp_session_action函数调用necp_session_find_from_fd来查询necp_session对象：

![image-20190324230459766](/Users/juwei_lin/Library/Application Support/typora-user-images/image-20190324230459766.png)

​	仔细看necp_session_find_from_fd，可以发现逻辑和necp_find_fd_data一模一样，都是验证fo_type是否为DTYPE_NETPOLICY。如果是，则返回fg_data为necp_session。

​	很显然，这是一个类型混淆漏洞，传入同样的句柄，调用necp_session_find_from_fd或者necp_find_fd_data都能成功得到同一地址值的内核对象，但是却被解释成不同的数据类型，前者是necp_fd_data，后者则是necp_session，而这两个数据结构是完全不一样的。	

​	这个类型混淆漏洞可以用来释放任意内核地址，接下来详细介绍一下如何实现任何地址释放。

​	第一步，调用necp_open创建一个necp_fd_data内核对象。

![image-20190324231618045](/Users/juwei_lin/Library/Application Support/typora-user-images/image-20190324231618045.png)

​	注意0x20处的update_list字段，update_list是一个双向链表的表头，被TAILQ_INIT宏初始化，所以我们得到的necp_fd_data对象如下：

![image-20190324231814186](/Users/juwei_lin/Library/Application Support/typora-user-images/image-20190324231814186.png)

​	第二步，传入necp_open的返回句柄，调用necp_session_action（注意正常情况下，应该只能调用necp_client_action才对，但这里存在类型混淆漏洞）。

​	因为传入的实际上是一个necp_fd_data内核对象而不是necp_session_action支持的necp_session对象，会发生什么神奇的事情呢？我们再来看看necp_session_action函数代码，如下所示：

![image-20190324232215719](/Users/juwei_lin/Library/Application Support/typora-user-images/image-20190324232215719.png)

​	在位置(b)处，如果session->proc_locked为false，session->proc_uuid和session->proc_pid的值会被更新。那么这三个字段是什么呢？来看看necp_session结构：

![image-20190324232433002](/Users/juwei_lin/Library/Application Support/typora-user-images/image-20190324232433002.png)

​	proc_locked偏移为0x20，大小为1个字节；proc_uuid偏移为0x21，大小0x10；proc_pid偏移为0x34，大小4个字节。因为传入的实际上是necp_fd_data对象，0x20处为update_list字段的第一个字节，值为0，即false，所以proc_uuid 和proc_pid会被更新，即0x21处会被更新为uuid，长度为0x10。此时该内核对象内存分布如下：

![image-20190324233045912](/Users/juwei_lin/Library/Application Support/typora-user-images/image-20190324233045912.png)

​	可以看到，update_list这个双向链表的表头已经被替换了，除了0x20处一个字节保留为0，其他的15个字节已经被替换为UUID的低15个字节了，而uuid是macho文件中的内容，即攻击者可控内容，所以我们可以通过控制uuid将update_list这16个字节的高15位替换成任意内容。

​	第三步，调用necp_client_action 释放任意地址。

​	我们使用necp_client_action的15号服务函数necp_client_copy_client_update来释放任意地址：

![image-20190324233553587](/Users/juwei_lin/Library/Application Support/typora-user-images/image-20190324233553587.png)

​	在位置(f)处，client_update实际上是update_list指向的第一个元素，即0x20处的8个字节值，在上一步中，我们已经将此处开始的高15个字节替换成任意内容了，所以client_update的值实际上由我们控制的7个高字节和一个0组成。

![image-20190324233810219](/Users/juwei_lin/Library/Application Support/typora-user-images/image-20190324233810219.png)

​	例如，我们将MachO的UUID设置为41414141414141414141414141414141，那么我们就释放了0x4141414141414100。所以实际上，我们并不是释放任意地址，准确地讲，我们可以释放高7字节可控的地址，且第一个字节始终为0。但这样已经非常有用了，因为内核对象是8字节对齐的，很容易找到。

​	最后，我们来看看苹果是如何修复这个漏洞的。苹果增加了一个sub type来区分necp_fd_data和necp_session对象：

![image-20190324234356275](/Users/juwei_lin/Library/Application Support/typora-user-images/image-20190324234356275.png)

## 二、 root介绍

​	我们现在可以使用CVE-2018-4413得到一个ipc_port的内核对象地址，再使用CVE-2018-4425释放这个内核对象，虽然有第一个字节为0的要求，但这里并没有问题，因为泄漏的ipc_port对象是我们创建的，如果不满足条件重新创建即可。

​	而如果你对Ian Beer的async_wake_ios比较熟悉，可以知道可以用我的两个漏洞完美套用async_wake_ios中的root技巧，其技巧简单描述如下：

1. 确保一整个page存储的全部是我们分配的ipc_port
2. 使用漏洞将目标ipc_port释放
3. 释放page上其他的ipc_port，使整个page处于释放状态
4. 触发gc，使得page能够跨zone被重新使用
5. 使用构造的ipc_kmsg重用page，ipc_kmsg将用fake_port填充page
6. 使用pid_for_task获得kernel task vm_map & ipc_space
7. 重新使用ipc_kmsg重用page，这次fake_port指向的fake_task包含了一个fake kernel task port
8. 获得tfp0，结束

​	推荐读者仔细阅读async_wake_ios的源码，本文不再详细介绍这个root技巧。如果有疑问，可以关注我的推特账号(@panicaII)联系我，谢谢阅读。



