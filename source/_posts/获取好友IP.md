---
title: 获取好友IP
date: 2020-03-24 16:54:40
updated: 2020-03-24 16:54:40
tags:
 - 无聊
 - 水文
categories: 
 - 日常水文
---

## 安装了火绒的方式

打开火绒剑点击Processes，找到QQ/微信的PID

1. 点击Fileter
2. 下拉选择Process Filter
3. 选择Process
4. 点击add 
5. 选择PID
6. Value填QQ/微信的PID
7. 切换到Action
8. 只选中MT_netmon
9. 点击OK

![](/pic/136.png)

![](/pic/137.png)

然后点击Start，此处已经点击了Start，所以变成Stop

![](/pic/138.png)

在Path处非8000端口即可能得到好友IP，此处因为本菜鸡多次测试（猜测，也能是网络不好），被腾讯强制连接到了腾讯的服务器

## 未安装火绒的方式

打开wireshark 选择上网网卡，双击

~~![](/pic/133.png)~~

~~点击搜索按钮（快捷键Ctrl+F），选择Packet details（中文：分组详情）,Sting(中文：字符串)~~

~~填入数据020048~~

~~![](/pic/134.png)~~

在搜索栏里输入udp.lenth==80（经过测试，拨打后未接通发送的数据包的大小是72，因为还有包头所以+8）

然后就可以拨打好友的电话



## 注意

多次挂断电话，再接通，会直接接入到腾讯服务器，从而后面就获取不到对方IP（此时电话以及接通）如下图

![](/pic/135.png)

对方QQ版本为QQ FOR win10(Microsoft  store中下载)，本菜鸡测试 ：未接通没有数据



## 题外话

腾讯连接的方式是如果检测到处于同一内网，QQ/TIM会直接点对点，这也就解释了为什么学校晚上断网后还能互发QQ消息。

**参考链接**

https://www.secpulse.com/archives/126081.html
https://www.cnblogs.com/Oran9e/p/7098097.html