---
title: buuoj刷题记录11-SUCTF复现
date: 2020-02-04 23:46:53
tags:
 - buuoj
 - web
 - suctf2019
---

## Pythonginx

题目给了源码

```
@app.route('/getUrl', methods=['GET', 'POST'])
def getUrl():
    url = request.args.get("url")
    host = parse.urlparse(url).hostname
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

parse.urlparse()函数：

将URL解析为六个组件，返回一个6个元素的元组，对应URL的一般结构：`scheme://netloc/path;parameters?query#fragment`



