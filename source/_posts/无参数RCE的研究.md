---
title: 无参数RCE的研究
date: 2020-04-30 22:49:16
updated: 2020-04-30 22:49:16
tags:
 - 无参数Rec
categories:
 - 日常积累
---

# 起因

在写一道简单的web题目时候遇到一个奇怪的正则表达式，在此记录一下

```
/[^\W]+\((?R)?\)/
```

# 分析

(?R)是递归匹配整个正则表达式，整个正则能匹配a(b(c(d()))),a(),a(b())这样的表达式，如果里面包含参赛就不能匹配到。

测试代码

```php
<?php
echo $_GET['cmd'];  
if(';' === preg_replace('/[^\W]+\((?R)?\)/', '', $_GET['code'])) {
  eval($_GET['cmd']);
}
```

传入参数phpinfo()；成功执行

```url
http://localhost/No_Pram_Rec.php?cmd=phpinfo();
```

![](/pic/151.png)

传入参数scandir(".");没有显示。

```url
http://localhost/No_Pram_Rec.php?cmd=scandir(".");
```

![](/pic/152.png)

也就是可以无限套函数，但是函数必须没有参数

# 利用

在skysec师傅的博客里面介绍了几种利用手法。

### 1. getenv()

getenv()获取的结果是数组，如何获取特定的数组元素是个问题。

可以使用array_rand() 

> 从数组中取出一个或多个随机的单元，并返回随机条目的一个或多个键。 它使用了伪随机数产生算法，所以不适合密码学场景。
>
> 如果只取出一个，**array_rand()** 返回随机单元的键名。 否则就返回包含随机键名的数组。 完成后，就可以根据随机的键获取数组的随机值。 取出数量如果超过 array 的长度，就会导致 **`E_WARNING`** 错误，并返回 NULL。

一般想要的内容都是数组的值，不是数组的键名。

此时可以使用

array_flip()

>交换数组的键名和值
>

相关的数组操作函数

- array_pop() 取最后一个数组

- Array_values() 返回数组所有值组成的数组（键名是0，1，2，3）
- array_reverse() 将数组逆序
- [end()](https://www.w3school.com.cn/php/func_array_end.asp) – 将内部指针指向数组中的最后一个元素，并输出键值 （参考来自颖奇师傅博客）
- [next()](https://www.w3school.com.cn/php/func_array_next.asp) – 将内部指针指向数组中的下一个元素，并输出键值
- [prev()](https://www.w3school.com.cn/php/func_array_prev.asp) – 将内部指针指向数组中的上一个元素，并输出键值
- [reset()](https://www.w3school.com.cn/php/func_array_reset.asp) – 将内部指针指向数组中的第一个元素，并输出键值
- [each()](https://www.w3school.com.cn/php/func_array_each.asp) – 返回当前元素的键名和键值，并将内部指针向前移动

### 2.getallheaders()

| 版本  | 说明                                                         |
| :---- | :----------------------------------------------------------- |
| 5.5.7 | 此函数可用于 CLI server。                                    |
| 5.4.0 | 此函数可用于 FastCGI。 此前仅在PHP以 Apache 模块方式运行时支持。 |
| 4.3.3 | 从 PHP 4.3.3 起，也可在 Netscape/iPlanet/SunONE Web 服务器的 [NSAPI 服务器模块](https://www.php.net/manual/zh/book.nsapi.php)使用此函数。 |
| 4.3.0 | 被改名而成为 [apache_request_headers()](https://www.php.net/manual/zh/function.apache-request-headers.php) 的别名。因为此函数仅适用于 Apache 。 |

此函数会返回httpheader头部形成一个数组

在此时可以使用自定义头部。达到rce

![](/pic/153.png)

### 3. get_defined_vars()

由于部分版本的php只能在apache上运行getallheaders()才有效果。所以当getallheaders()失效时，可以采取本函数。

![](/pic/155.png)

能返回`_GET`、`_POST`、`_COOKIE`、`_FILES`数组

选取`_GET`进行RCE

![](/pic/156.png)

尝试`_FILES`数组（`_POST`、`_COOKIE`也是同样的用法）

通过文件名进行RCE（也可以使用MIME）

空格会被截断，所以需要进行编码，此处采用base64编码

![](/pic/157.png)

### 4. session_id()

这里是使用`_COOKIE`数组，除了直接利用get_defined_vars()，还能利用session_id()

>- [session_get_cookie_params](https://www.php.net/manual/zh/function.session-get-cookie-params.php) — 获取会话 cookie 参数
>- [session_id](https://www.php.net/manual/zh/function.session-id.php) — 获取/设置当前会话 ID
>- [session_name](https://www.php.net/manual/zh/function.session-name.php) — 读取/设置会话名称
>- [session_start](https://www.php.net/manual/zh/function.session-start.php) — 启动新会话或者重用现有会话

经过测试发现PHPSESSID允许字母和数字出现

