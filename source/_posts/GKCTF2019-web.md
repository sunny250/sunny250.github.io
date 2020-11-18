---
title: GKCTF2019-web
date: 2020-05-26 20:09:17
updated: 2020-05-26 20:09:17
tags:
 - GKCTF
categories:
 - 日常刷题

---

# web

## [GKCTF2020]CheckIN

打开题目就有源码

```php
<?php 
highlight_file(__FILE__);
class ClassName
{
        public $code = null;
        public $decode = null;
        function __construct()
        {
                $this->code = @$this->x()['Ginkgo'];
                $this->decode = @base64_decode( $this->code );
                @Eval($this->decode);
        }

        public function x()
        {
                return $_REQUEST;
        }
}
new ClassName();
```

