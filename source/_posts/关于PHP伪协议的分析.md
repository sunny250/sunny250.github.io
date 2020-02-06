---
title: 关于PHP伪协议的分析
date: 2020-01-03 20:17:47
tags:
 - php
 - web
---

### 0X00 简介

PHP支持的协议和封装协议

- [file://](https://www.php.net/manual/zh/wrappers.file.php)   

- [http://](https://www.php.net/manual/zh/wrappers.http.php)

- [ftp://](https://www.php.net/manual/zh/wrappers.ftp.php)

- [php://](https://www.php.net/manual/zh/wrappers.php.php)     

  <!--more-->

- [zlib://](https://www.php.net/manual/zh/wrappers.compression.php)

- [data://](https://www.php.net/manual/zh/wrappers.data.php)    

- [glob://](https://www.php.net/manual/zh/wrappers.glob.php)

- [phar://](https://www.php.net/manual/zh/wrappers.phar.php)

- [ssh2://](https://www.php.net/manual/zh/wrappers.ssh2.php)

- [rar://](https://www.php.net/manual/zh/wrappers.rar.php)

- [ogg://](https://www.php.net/manual/zh/wrappers.audio.php)

- [expect://](https://www.php.net/manual/zh/wrappers.expect.php)

常见的文件包含函数：

**1. include函数**

通过get方法或post方法include的文件首先是从当前文件夹下开始读取，此时目录穿越漏洞可以用

不能够读取自己，否则会出现逻辑错误

如果直接包含一个php文件，则只会显示其中在标签外的内容，以及php代码输出的内容

若要读取php文件的内容，则需要将其编码，例：php://filter/read=convert.base64-encode/resource=123.php

使用时如果有多个文件符合，只会输出第一个

**2. highlight_file函数**

将文件以内置的颜色输出，可以输出php文件，也可以输出其他文件
如果第二个参数return设置为true，那么文件内容将不会输出，而是返回一个字符串

#### 3. show_source函数

上面函数的别名，功能是一样的

**4. file_get_contents函数**

将一个文件读入一个字符串
包含的文件需要在源码中才能看到，或者使用伪协议将其base64加密

**5. fopen函数**

因为返回的是一个指针，所以不能够直接读取，需要用fgets或者fread读取指针指向的内容，或者使用fpassthru读取指针指向剩下的内容

**6. readfile函数**

功能是读取一个文件到缓冲区，返回一个整数(为文件的内字符的长度)

**7. file函数**

功能是将一个文件读入数组，数组的键是行数(从0开始),数组的值为该行的内容



allow_url_fopen ：on  默认开启  该选项为on便是激活了 URL 形式的 fopen 封装协议使得可以访问 URL 对象文件等。

allow_url_include：off  默认关闭，该选项为on便是允许 包含URL 对象文件等。

### 0x01  file://

file://不受`allow_url_fopen、allow_url_include·`影响

> file:// [文件的绝对路径和文件名]

http://127.0.0.1/temp.php?file=file:///wamp/www/1.php


```
<?php
include($_GET['file']);
?>
```

![](/pic/14.png)

**截断**

若读取的文件为非PHP后缀，在php版本<=5.2可使用%00截断

```
<?php
include($_GET['file'].’.php’);
?>
```

### 0x02 php://

无需`allow_url_fopen on`，仅`php://input、 php://stdin、 php://memory 、php://temp` 需要开启`allow_url_include`。

php:// 访问各个输入/输出流（I/O streams）

1. #### php://filter 

| 属性                                                         | 支持                                                         |
| :----------------------------------------------------------- | :----------------------------------------------------------- |
| 受限于 [allow_url_fopen](https://www.php.net/manual/zh/filesystem.configuration.php#ini.allow-url-fopen) | No                                                           |
| 受限于 [allow_url_include](https://www.php.net/manual/zh/filesystem.configuration.php#ini.allow-url-include) | 仅 *php://input*、 *php://stdin*、 *php://memory* 和 *php://temp*。 |
| 允许读取                                                     | 仅 *php://stdin*、 *php://input*、 *php://fd*、 *php://memory* 和 *php://temp*。 |
| 允许写入                                                     | 仅 *php://stdout*、 *php://stderr*、 *php://output*、 *php://fd*、 *php://memory* 和 *php://temp*。 |
| 允许追加                                                     | 仅 *php://stdout*、 *php://stderr*、 *php://output*、 *php://fd*、 *php://memory* 和 *php://temp*（等于写入） |
| 允许同时读写                                                 | 仅 *php://fd*、 *php://memory* 和 *php://temp*。             |
| 支持 [stat()](https://www.php.net/manual/zh/function.stat.php) | 仅 *php://memory* 和 *php://temp*。                          |
| 支持 [unlink()](https://www.php.net/manual/zh/function.unlink.php) | No                                                           |
| 支持 [rename()](https://www.php.net/manual/zh/function.rename.php) | No                                                           |
| 支持 [mkdir()](https://www.php.net/manual/zh/function.mkdir.php) | No                                                           |
| 支持 [rmdir()](https://www.php.net/manual/zh/function.rmdir.php) | No                                                           |
| 仅仅支持 [stream_select()](https://www.php.net/manual/zh/function.stream-select.php) | *php://stdin*、 *php://stdout*、 *php://stderr*、 *php://fd* 和 *php://temp*。 |

​	a. 多用于读取源码php://filter/read=convert.base64-encode/resource=   （*include、highlight_file、show_source、readfile*可用）

| 名称                        | 描述                                                         |
| :-------------------------- | :----------------------------------------------------------- |
| *resource=<要过滤的数据流>* | 这个参数是必须的。它指定了你要筛选过滤的数据流。             |
| *read=<读链的筛选列表>*     | 该参数可选。可以设定一个或多个过滤器名称，以管道符（*\|*）分隔。 |
| *write=<写链的筛选列表>*    | 该参数可选。可以设定一个或多个过滤器名称，以管道符（*\|*）分隔。 |
| *<；两个链的筛选列表>*      | 任何没有以 *read=* 或 *write=* 作前缀 的筛选器列表会视情况应用于读或写链。 |

常用筛选过滤列表

> 1. string.rot13  rot13加密
> 2. string.toupper   转换成大写
> 3. string.tolower   转换成小写
> 4. string.srip_tags   去除标签
> 5. convert.base64-encode & convert.base64-decode
> 6. convert.quoted-printable-encode & convert.quoted-printable-decode

![](/pic/15.png)

![](/pic/16.png)

![](/pic/17.png)已经把< >中的数据去除 所以已经没有数据



2. #### php://input

    *enctype="multipart/form-data"* 的时候 php://input 是无效的。此协议多用于命令执行需要**allow_url_include：on**

​      ![](/pic/18.png) 

​       ![](/pic/19.png)

3. ### php://output 

   php://output 是一个只写的数据流， 允许你以 [print](https://www.php.net/manual/zh/function.print.php) 和 [echo](https://www.php.net/manual/zh/function.echo.php) 一样的方式 写入到输出缓冲区。

### 0x03 zip://, bzip2://, zlib://协议

zip://, bzip2://, zlib:// 均属于压缩流，可以访问压缩文件中的子文件，更重要的是不需要指定后缀名。

| 属性                                                         | 支持                                            |
| :----------------------------------------------------------- | :---------------------------------------------- |
| 受限于 [allow_url_fopen](https://www.php.net/manual/zh/filesystem.configuration.php#ini.allow-url-fopen) | No                                              |
| 允许读取                                                     | Yes                                             |
| 允许写入                                                     | Yes（除了 *zip://*）                            |
| 允许附加                                                     | Yes（除了 *zip://*）                            |
| 允许同时读写                                                 | No                                              |
| 支持 [stat()](https://www.php.net/manual/zh/function.stat.php) | No，请使用普通的 *file://* 封装器统计压缩文件。 |
| 支持 [unlink()](https://www.php.net/manual/zh/function.unlink.php) | No，请使用 *file://* 封装器删除压缩文件。       |
| 支持 [rename()](https://www.php.net/manual/zh/function.rename.php) | No                                              |
| 支持 [mkdir()](https://www.php.net/manual/zh/function.mkdir.php) | No                                              |
| 支持 [rmdir()](https://www.php.net/manual/zh/function.rmdir.php) | No                                              |

#### 1. zip://协议

zip:// [压缩文件路径]#[压缩文件内的子文件]

测试失败 ,报错

**【bzip2://协议】**

**使用方法：**

compress.bzip2://[压缩文件地址]

测试失败 没有返回数据

#### 3. zlib://协议

compress.zlib://[压缩文件地址]

![](/pic/20.png)

### 0x04 data://

经过测试官方文档上存在问题，经过测试data:// 协议是是受限于allow_url_fopen的，官方文档上给出的是NO

| 属性                                                         | 支持 |
| :----------------------------------------------------------- | :--- |
| 受限于 [allow_url_fopen](https://www.php.net/manual/zh/filesystem.configuration.php#ini.allow-url-fopen) | Yes  |
| 受限于 [allow_url_include](https://www.php.net/manual/zh/filesystem.configuration.php#ini.allow-url-include) | Yes  |
| 允许读取                                                     | Yes  |
| 允许写入                                                     | No   |
| 允许追加                                                     | No   |
| 允许同时读写                                                 | No   |
| 支持 [stat()](https://www.php.net/manual/zh/function.stat.php) | No   |
| 支持 [unlink()](https://www.php.net/manual/zh/function.unlink.php) | No   |
| 支持 [rename()](https://www.php.net/manual/zh/function.rename.php) | No   |
| 支持 [mkdir()](https://www.php.net/manual/zh/function.mkdir.php) | No   |
| 支持 [rmdir()](https://www.php.net/manual/zh/function.rmdir.php) | No   |

http://localhost/temp.php?file=data://text/plain,<?php phpinfo()?>

http://localhost/temp.php?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpPz4=

http://localhost/temp.php?file=data:text/plain,<?php phpinfo()?>

http://localhost/temp.php?file=data:text/plain;base64,PD9waHAgcGhwaW5mbygpPz4=

![](/pic/21.png)

### 0x05 总结

![](/pic/22.png)