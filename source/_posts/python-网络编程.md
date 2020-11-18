---
title: python 网络编程
date: 2020-03-14 15:11:38
updated: 2020-03-14 15:11:38
tags:
 - 
categories:
 - 日常积累
---

# 前言

在学校的课程中学到了有关网络编程的内容，在此记录一下。

<!--more-->

实验要求

1. 是使用tcp、udp实现一个客户端与服务器的通信
2. 使用原始套接字实现ping命令
3. 实现GUI的客户端与服务器通信
4. 实现GUI的简易浏览器
5. 实现GUI的简单文件传输
6. 实现GUI多人聊天系统

# 学习py相关的库

**socket库**（参考自[菜鸟教程](https://www.runoob.com/python/python-socket.html)、[py官网](https://docs.python.org/zh-cn/3/library/socket.html)）

使用socket.socket()创建套接字

```
socket.socket([family[, type[, proto]]])
family: 套接字家族可以使AF_UNIX或者AF_INET（AF_INET6表示ipv6版本）
type: SOCK_STREAM（TCP）、SOCK_DGRAM(UDP)、socket.SOCK_RAW（原始套接字）
protocol: 一般不填默认为0
```

| 函数                                 | 描述                                                         |
| :----------------------------------- | :----------------------------------------------------------- |
| 服务器端套接字                       |                                                              |
| s.bind()                             | 绑定地址（host,port）到套接字， 在AF_INET下,以元组（host,port）的形式表示地址。 |
| s.listen()                           | 开始TCP监听。backlog指定在拒绝连接之前，操作系统可以挂起的最大连接数量。该值至少为1，大部分应用程序设为5就可以了。 |
| s.accept()                           | 被动接受TCP客户端连接,(阻塞式)等待连接的到来                 |
| 客户端套接字                         |                                                              |
| s.connect()                          | 主动初始化TCP服务器连接，。一般address的格式为元组（hostname,port），如果连接出错，返回socket.error错误。 |
| s.connect_ex()                       | connect()函数的扩展版本,出错时返回出错码,而不是抛出异常      |
| 公共用途的套接字函数                 |                                                              |
| s.recv()                             | 接收TCP数据，数据以字符串形式返回，bufsize指定要接收的最大数据量。flag提供有关消息的其他信息，通常可以忽略。 |
| s.send()                             | 发送TCP数据，将string中的数据发送到连接的套接字。返回值是要发送的字节数量，该数量可能小于string的字节大小。 |
| s.sendall()                          | 完整发送TCP数据，完整发送TCP数据。将string中的数据发送到连接的套接字，但在返回之前会尝试发送所有数据。成功返回None，失败则抛出异常。 |
| s.recvfrom()                         | 接收UDP数据，与recv()类似，但返回值是（data,address）。其中data是包含接收数据的字符串，address是发送数据的套接字地址。 |
| s.sendto()                           | 发送UDP数据，将数据发送到套接字，address是形式为（ipaddr，port）的元组，指定远程地址。返回值是发送的字节数。 |
| s.close()                            | 关闭套接字                                                   |
| s.getpeername()                      | 返回连接套接字的远程地址。返回值通常是元组（ipaddr,port）。  |
| s.getsockname()                      | 返回套接字自己的地址。通常是一个元组(ipaddr,port)            |
| s.setsockopt(level,optname,value)    | 设置给定套接字选项的值。                                     |
| s.getsockopt(level,optname[.buflen]) | 返回套接字选项的值。                                         |
| s.settimeout(timeout)                | 设置套接字操作的超时期，timeout是一个浮点数，单位是秒。值为None表示没有超时期。一般，超时期应该在刚创建套接字时设置，因为它们可能用于连接的操作（如connect()） |
| s.gettimeout()                       | 返回当前超时期的值，单位是秒，如果没有设置超时期，则返回None。 |
| s.fileno()                           | 返回套接字的文件描述符。                                     |
| s.setblocking(flag)                  | 如果flag为0，则将套接字设为非阻塞模式，否则将套接字设为阻塞模式（默认值）。非阻塞模式下，如果调用recv()没有发现任何数据，或send()调用无法立即发送数据，那么将引起socket.error异常。 |
| s.makefile()                         | 创建一个与该套接字相关连的文件                               |

# 编写代码

### 1.  服务端与客户端通信

#### a. TCP

```python
# Client.py

# -*- coding: utf-8 -*-
# @Author  : sunny250
import socket
import tkinter

cilent=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
# print(socket.gethostbyaddr(8.8.8.8))
port=14153
host=socket.gethostname()
cilent.connect((host,port))
print(cilent.recv(1024).decode())

# cilent.close()
while 1:
    msg=input()
    if msg=='q!':
        cilent.send(msg.encode())
        cilent.close()
        break
    cilent.send(msg.encode())
    print(cilent.recv(1024).decode())
```

```python
# Server.py

# -*- coding: utf-8 -*-
# @Author  : sunny250
import socket
import time

server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

host=socket.gethostname()
# print(host)
port=14153
server.bind((host,port))
server.listen(6)
while 1:
    # server.bind((host, port))
    # server.listen(5)
    c,caddr=server.accept()
    chost,cport=caddr
    c.send('已成功连接到服务器，你的地址是：'.encode()+chost.encode()+'端口是：'.encode()+str(cport).encode())
    # c.close()
    msg=''
    while msg!='q!':
        msg=c.recv(1024).decode()
        smsg=time.ctime()+' '+chost+':'+str(cport)+'说'+'\n'+msg
        print(smsg)
        c.send(smsg.encode())
    c.close()
```

#### b.UDP

```python
# Client.py

# -*- coding: utf-8 -*-
# @Author  : sunny250
import socket

client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

port=14153
host="127.0.0.1"
addr=(host,port)

client.sendto('hello'.encode(), addr)
msg,saddr=client.recvfrom(1024)
print(msg.decode())

while 1:
    msg=input()
    if msg=='q!':
        client.sendto(msg.encode(), addr)
        client.close()
        break
    client.sendto(msg.encode(),addr)
    rmsg,saddr=client.recvfrom(1024)
    print(rmsg.decode())
```

```python
# Server.py

# -*- coding: utf-8 -*-
# @Author  : sunny250
import socket
import time

server = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

host="127.0.0.1"
port=14153

server.bind((host,port))

while 1:
    msg, caddr = server.recvfrom(1024)   #msg是服务器接受到客户端的数据，caddr是client的IP和端口
    chost,cport=caddr   #chost 即clienthost 客户端IP，cport客户端端口
    server.sendto('已成功连接到服务器，你的地址是：'.encode()+chost.encode()+'端口是：'.encode()+str(cport).encode(),caddr)
    msg=''
    while msg!='q!':
        msg,caddr=server.recvfrom(1024)
        smsg=time.ctime()+' '+chost+':'+str(cport)+'说'+'\n'+msg.decode()
        print(smsg)
        server.sendto(smsg.encode(),caddr)
    c.close()
```

### 2. 原始套接字实现ping命令

套接字要实现对原始数据包的处理，需要了解数据包的格式参考来自[C语言中文网](http://c.biancheng.net/view/6411.html)

![](/pic/158.png)

#### 1) 版本（version）

占 4 位，表示 IP 协议的版本。通信双方使用的 IP 协议版本必须一致。目前广泛使用的IP协议版本号为 4，即 IPv4。

#### 2) 首部长度（网际报头长度IHL）

占 4 位，可表示的最大十进制数值是 15。这个字段所表示数的单位是 32 位字长（1 个 32 位字长是 4 字节）。因此，当 IP 的首部长度为 1111 时（即十进制的 15），首部长度就达到 60 字节。当 IP 分组的首部长度不是 4 字节的整数倍时，必须利用最后的填充字段加以填充。

数据部分永远在 4 字节的整数倍开始，这样在实现 IP 协议时较为方便。首部长度限制为 60 字节的缺点是，长度有时可能不够用，之所以限制长度为 60 字节，是希望用户尽量减少开销。最常用的首部长度就是 20 字节（即首部长度为 0101），这时不使用任何选项。

#### 3) 区分服务（tos）

也被称为服务类型，占 8 位，用来获得更好的服务。这个字段在旧标准中叫做服务类型，但实际上一直没有被使用过。1998 年 IETF 把这个字段改名为区分服务（Differentiated Services，DS）。只有在使用区分服务时，这个字段才起作用。

#### 4) 总长度（totlen）

首部和数据之和，单位为字节。总长度字段为 16 位，因此数据报的最大长度为 2^16-1=65535 字节。

#### 5) 标识（identification）

用来标识数据报，占 16 位。IP 协议在存储器中维持一个计数器。每产生一个数据报，计数器就加 1，并将此值赋给标识字段。当数据报的长度超过网络的 MTU，而必须分片时，这个标识字段的值就被复制到所有的数据报的标识字段中。具有相同的标识字段值的分片报文会被重组成原来的数据报。

#### 6) 标志（flag）

占 3 位。第一位未使用，其值为 0。第二位称为 DF（不分片），表示是否允许分片。取值为 0 时，表示允许分片；取值为 1 时，表示不允许分片。第三位称为 MF（更多分片），表示是否还有分片正在传输，设置为 0 时，表示没有更多分片需要发送，或数据报没有分片。

#### 7) 片偏移（offsetfrag）

占 13 位。当报文被分片后，该字段标记该分片在原报文中的相对位置。片偏移以 8 个字节为偏移单位。所以，除了最后一个分片，其他分片的偏移值都是 8 字节（64 位）的整数倍。

#### 8) 生存时间（TTL）

表示数据报在网络中的寿命，占 8 位。该字段由发出数据报的源主机设置。其目的是防止无法交付的数据报无限制地在网络中传输，从而消耗网络资源。

路由器在转发数据报之前，先把 TTL 值减 1。若 TTL 值减少到 0，则丢弃这个数据报，不再转发。因此，TTL 指明数据报在网络中最多可经过多少个路由器。TTL 的最大数值为 255。若把 TTL 的初始值设为 1，则表示这个数据报只能在本局域网中传送。 

#### 9) 协议

表示该数据报文所携带的数据所使用的协议类型，占 8 位。该字段可以方便目的主机的 IP 层知道按照什么协议来处理数据部分。不同的协议有专门不同的协议号。

例如，TCP 的协议号为 6，UDP 的协议号为 17，ICMP 的协议号为 1。

#### 10) 首部检验和（checksum）

用于校验数据报的首部，占 16 位。数据报每经过一个路由器，首部的字段都可能发生变化（如TTL），所以需要重新校验。而数据部分不发生变化，所以不用重新生成校验值。

#### 11) 源地址

表示数据报的源 IP 地址，占 32 位。

#### 12) 目的地址

表示数据报的目的 IP 地址，占 32 位。该字段用于校验发送是否正确。

#### 13) 可选字段

该字段用于一些可选的报头设置，主要用于测试、调试和安全的目的。这些选项包括严格源路由（数据报必须经过指定的路由）、网际时间戳（经过每个路由器时的时间戳记录）和安全限制。

#### 14) 填充

由于可选字段中的长度不是固定的，使用若干个 0 填充该字段，可以保证整个报头的长度是 32 位的整数倍。

#### 15) 数据部分

表示传输层的数据，如保存 TCP、UDP、ICMP 或 IGMP 的数据。数据部分的长度不固定。



#### 16) TCP/UDP/ICMP报文格式

1. TCP

   ![](/pic/159.png)

   ###### 源端口和目的端口字段

   - TCP源端口（Source Port）：源计算机上的应用程序的端口号，占 16 位。
   - TCP目的端口（Destination Port）：目标计算机的应用程序端口号，占 16 位。

   ###### 序列号字段

   CP序列号（Sequence Number）：占 32 位。它表示本报文段所发送数据的第一个字节的编号。在 TCP 连接中，所传送的字节流的每一个字节都会按顺序编号。当SYN标记不为1时，这是当前数据分段第一个字母的序列号；如果SYN的值是1时，这个字段的值就是初始序列值（ISN），用于对序列号进行同步。这时，第一个字节的序列号比这个字段的值大1，也就是ISN加1。

   ###### 确认号字段

   TCP 确认号（Acknowledgment Number，ACK Number）：占 32 位。它表示接收方期望收到发送方下一个报文段的第一个字节数据的编号。其值是接收计算机即将接收到的下一个序列号，也就是下一个接收到的字节的序列号加1。

   ###### 数据偏移字段

   TCP 首部长度（Header Length）：数据偏移是指数据段中的“数据”部分起始处距离 TCP 数据段起始处的字节偏移量，占 4 位。其实这里的“数据偏移”也是在确定 TCP 数据段头部分的长度，告诉接收端的应用程序，数据从何处开始。

   ###### 保留字段

   保留（Reserved）：占 4 位。为 TCP 将来的发展预留空间，目前必须全部为 0。

   ###### 标志位字段

   - CWR（Congestion Window Reduce）：拥塞窗口减少标志，用来表明它接收到了设置 ECE 标志的 TCP 包。并且，发送方收到消息之后，通过减小发送窗口的大小来降低发送速率。
   - ECE（ECN Echo）：用来在 TCP 三次握手时表明一个 TCP 端是具备 ECN 功能的。在数据传输过程中，它也用来表明接收到的 TCP 包的 IP 头部的 ECN 被设置为 11，即网络线路拥堵。
   - URG（Urgent）：表示本报文段中发送的数据是否包含紧急数据。URG=1 时表示有紧急数据。当 URG=1 时，后面的紧急指针字段才有效。
   - ACK：表示前面的确认号字段是否有效。ACK=1 时表示有效。只有当 ACK=1 时，前面的确认号字段才有效。TCP 规定，连接建立后，ACK 必须为 1。
   - PSH（Push）：告诉对方收到该报文段后是否立即把数据推送给上层。如果值为 1，表示应当立即把数据提交给上层，而不是缓存起来。
   - RST：表示是否重置连接。如果 RST=1，说明 TCP 连接出现了严重错误（如主机崩溃），必须释放连接，然后再重新建立连接。
   - SYN：在建立连接时使用，用来同步序号。当 SYN=1，ACK=0 时，表示这是一个请求建立连接的报文段；当 SYN=1，ACK=1 时，表示对方同意建立连接。SYN=1 时，说明这是一个请求建立连接或同意建立连接的报文。只有在前两次握手中 SYN 才为 1。
   - FIN：标记数据是否发送完毕。如果 FIN=1，表示数据已经发送完成，可以释放连接。

   ###### 窗口大小字段

   窗口大小（Window Size）：占 16 位。它表示从 Ack Number 开始还可以接收多少字节的数据量，也表示当前接收端的接收窗口还有多少剩余空间。该字段可以用于 TCP 的流量控制。

   ###### TCP 校验和字段

   校验位（TCP Checksum）：占 16 位。它用于确认传输的数据是否有损坏。发送端基于数据内容校验生成一个数值，接收端根据接收的数据校验生成一个值。两个值必须相同，才能证明数据是有效的。如果两个值不同，则丢掉这个数据包。Checksum 是根据伪头 + TCP 头 + TCP 数据三部分进行计算的。

   ###### 紧急指针字段

   紧急指针（Urgent Pointer）：仅当前面的 URG 控制位为 1 时才有意义。它指出本数据段中为紧急数据的字节数，占 16 位。当所有紧急数据处理完后，TCP 就会告诉应用程序恢复到正常操作。即使当前窗口大小为 0，也是可以发送紧急数据的，因为紧急数据无须缓存。

   ###### 可选项字段

   选项（Option）：长度不定，但长度必须是 32bits 的整数倍。

2. UDP

   +-------------------------+--------------------------+
   |   16位源端口号   ｜   16位源端口号    ｜
   +-------------------------+--------------------------+
   |   16位源端口号   ｜   16位源端口号    ｜
   +-------------------------+--------------------------+
   |                            数据                             ｜
   +-------------------------+--------------------------+

   - 源端口：16位，标识本地端口
   - 目的端口：16位，标识目标端口
   - 总长度：标识该报文段包括报头部分的所有数据字节的长度。
   - 校验和：计算方式和TCP相似
   - 数据：可变长度

3. ICMP

   +-------------------------+--------------------------+---------------------------+
   |         8位类型       ｜         8位代码        ｜       16位校验和     ｜
   +-------------------------+--------------------------+---------------------------+
   |             16位 标识符              ｜           序列号16位                  ｜
   +---------------------------------------+-----------------------------------------+
   |                                        选项（若有）                                      ｜
   +---------------------------------------+-----------------------------------------+
   
   | 类型 | 代码 | 含义                         |
   | ---- | ---- | ---------------------------- |
   | 0    | 0    | 回显应答（ping 应答）        |
   | 3    | 0    | 网络不可达                   |
   | 3    | 1    | 主机不可达                   |
   | 3    | 2    | 协议不可达                   |
   | 3    | 3    | 端口不可达                   |
   | 3    | 4    | 需要进行分片，但设置不分片位 |
   | 3    | 5    | 源站选路失败                 |
   | 3    | 6    | 目的网络未知                 |
   | 3    | 7    | 目的主机未知                 |
   | 3    | 9    | 目的网络被强制禁止           |
   | 3    | 10   | 目的主机被强制禁止           |
   | 3    | 11   | 由于服务类型 TOS，网络不可达 |
   | 3    | 12   | 由于服务类型 TOS，主机不可达 |
   | 3    | 13   | 由于过滤，通信被强制禁止     |
   | 3    | 14   | 主机越权                     |
   | 3    | 15   | 优先中止失效                 |
   | 4    | 0    | 源端被关闭（基本流控制）     |
   | 5    | 0    | 对网络重定向                 |
   | 5    | 1    | 对主机重定向                 |
   | 5    | 2    | 对服务类型和网络重定向       |
   | 5    | 3    | 对服务类型和主机重定向       |
   | 8    | 0    | 回显请求（ping 请求）        |
   | 9    | 0    | 路由器通告                   |
   | 10   | 0    | 路由器请求                   |
   | 11   | 0    | 传输期间生存时间为 0         |
   | 11   | 1    | 在数据报组装期间生存时间为 0 |
   | 12   | 0    | 坏的 IP 首部                 |
   | 12   | 1    | 缺少必需的选项               |
   | 13   | 0    | 时间戳请求                   |
   | 14   | 0    | 时间戳应答                   |
   | 17   | 0    | 地址掩码请求                 |
   | 18   | 0    | 地址掩码应答                 |

校验和计算

在发送数据时，为了计算数据包的校验和。应该按如下步骤：
（1）把校验和字段置为0；　　
（2）把需校验的数据看成以16位为单位的数字组成，依次进行二进制反码求和；
（3）把得到的结果存入校验和字段中。　　在接收数据时，计算数据包的校验和相对简单，按如下步骤：

> （1）把首部看成以16位为单位的数字组成，依次进行二进制反码求和，包括校验和字段；　　
> （2）检查计算出的校验和的结果是否为0；
> （3）如果等于0，说明被整除，校验是和正确。否则，校验和就是错误的，协议栈要抛弃这个数据包。

虽然上面四种报文的校验和算法一样，但在作用范围存在不同：IP校验和只校验20字节的IP报头；而ICMP校验和覆盖整个报文（ICMP报头+ICMP数据）；UDP和TCP校验和不仅覆盖整个报文，而且还有12字节的IP伪首部，包括源IP地址(4字节)、目的IP地址(4字节)、协议(2字节，第一字节补0)和TCP/UDP包长(2字节)。另外UDP、TCP数据报的长度可以为奇数字节，所以在计算校验和时需要在最后增加填充字节0（注意，填充字节只是为了计算校验和，可以不被传送）。

```python
# -*- coding: utf-8 -*-
# @Author  : sunny250
import socket
import struct
import binascii

def icmp_check(data):
    print(data)
    length = len(data)
    flag = length % 2  # 判断data长度是否是偶数字节
    sum = 0  # 记录(十进制)相加的结果
    data=binascii.b2a_hex(data)
    print(data)
    for i in range(0, len(data), 4):  # 将每两个字节(16位)相加（二进制求和）直到最后得出结果
        sum += int(data[i+2:i+4]+data[i:i+2],16) # 传入data以每两个字节（十六进制）通过ord转十进制，第一字节在低位，第二个字节在高位\

    if flag:  # 传入的data长度是奇数，将执行，且把这个字节（8位）加到前面的结果
        sum += int(data[-2:],16)
    print(hex(sum))
    # 将高于16位与低16位相加
    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16)  # 如果还有高于16位，将继续与低16位相加
    answer = ~sum & 0xffff  # 对sum取反(返回的是十进制)
    # 主机字节序转网络字节序列（参考小端序转大端序）
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer  # 最终返回的结果就是wireshark里面看到的checksum校验和


def icmp_pack():
    # icmp header
    icmp_type = 8
    icmp_code = 0
    icmp_check_sum = 0
    icmp_id = 1
    icmp_seq = 11
    icmp_date = b'Hello!'

    icmp_header = struct.pack('!BBHHH6s', icmp_type, icmp_code, icmp_check_sum, icmp_id, icmp_seq, icmp_date)
    icmp_check_sum=icmp_check(icmp_header)

    icmp_header = struct.pack('!BBHHH6s', icmp_type, icmp_code, icmp_check_sum, icmp_id, icmp_seq, icmp_date)

    return icmp_header


def main(ip):
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    packets = icmp_pack()
    raw_sock.sendto(packets, (ip, 0))
    reply_date,address=raw_sock.recvfrom(1024)
    reply_date=struct.unpack('!BBHHHBBH4s4sBBHHH6s',reply_date)
    # print(binascii.b2a_hex(reply_date))
    print('Success! Host is up, the reply from ',ip,' ttl is ',reply_date[5])

if __name__ == '__main__':
    main('127.0.0.1')
```

