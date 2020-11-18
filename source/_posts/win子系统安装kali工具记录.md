---
title: win子系统安装kali工具记录
date: 2020-03-05 04:08:48
tags:
 - 工具安装
---

win下的子系统kali默认是不带有Metasploit

如果是其他linux安装需要换源

<!--more-->

```
vim /etc/apt/sources.list
```

会自动选取最近的源服务器

```
deb http://http.kali.org/kali kali-rolling main non-free contrib
deb-src http://http.kali.org/kali kali-rolling main non-free contrib
```

换好之后就是更新一下

```
apt update
```

下载需要的工具例如Matesploit

```
sudo apt-get install metasploit-framework
```

安装好之后需要初始化postgres数据库

```
sudo msfdb init
```

安装ncat，sqlmap，nmap,aircrack-ng等

```
sudo apt-get -y insatll ncat
sudo apt-get -y insatll sqlmap
sudo apt-get -y insatll nmap
sudo apt-get -y insatll aircrack-ng
```



在安装完wireshark后运行报错

```
sx@QAQ:~$ wireshark
wireshark: error while loading shared libraries: libQt5Core.so.5: cannot open shared object file: No such file or directory
```

删除标签即可参考链接https://github.com/Microsoft/WSL/issues/3023

```
 sudo strip --remove-section=.note.ABI-tag /usr/lib/x86_64-linux-gnu/libQt5Core.so.5.12.5
```



记录一下更改用户名以及家目录

```
usermod -l NewUser -d /home/NewUser -m OldUser
```



直接ping host

```
ping: socket: Operation not permitted
```

sudo ping 后正常

```
$ sudo ping 1.1.1.1
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=64 time=188 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=64 time=188 ms
64 bytes from 1.1.1.1: icmp_seq=3 ttl=64 time=191 ms
64 bytes from 1.1.1.1: icmp_seq=4 ttl=64 time=187 ms
```

解决办法   chmod +s 就是给某个程序暂时root权限，运行后恢复正常权限

```
$ type ping
ping is hashed (/usr/bin/ping)
$ sudo chmod +s /usr/bin/ping
```

