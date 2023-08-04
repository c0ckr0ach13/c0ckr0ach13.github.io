---
title: pyjail bypass-09 绕过输出限制
date: 2023-08-03 10:23:57
categories:
- Python
tags:
- pyjail
toc: true
---


# PyJail 没有输出的场景
在 Python 中使用 exec 函数执行代码时，默认情况下没有输出，如果想要再 exec 中打印结果，就需要在执行代码块时假如 print。

以 AmateursCTF 2023 的一道题目为例，题目的源码如下：
```py
#!/usr/local/bin/python
from flag import flag

for _ in [flag]:
    while True:
        try:
            code = ascii(input("Give code: "))
            if "flag" in code or "e" in code or "t" in code or "\\" in code:
                raise ValueError("invalid input")
            exec(eval(code))
        except Exception as err:
            print(err)
```

在这道题中，首先通过 ascii 将输入进行转化，使用 ascii 后，即使 unicode，也会被转化为 \\u00xx 的形式。然后判断输入中是否出现了 flag、e、t、以及 \\。这样的过滤条件基本将 unicode 绕过的方式给限制住了。过滤了 e 和 t， print、help 等输出函数也会被过滤， 而题目使用 exec 来执行 python 代码，因此除了绕过过滤之外，还需要考虑如何获取输出。

注意到这道题添加了一个异常处理，如果 exec 中出现错误，则会将错误信息打印出来，借助异常处理的输出，就可以将 Python 中的一些内部变量给带出来。

# 利用异常处理
作为客户端输入，结合当前读取变量的场景，python 中可利用的一些异常大多为：
- KeyError（键错误）： 当访问字典中不存在的键时引发的错误。（用户输入的键名被应用使用）
- FileNotFoundError（文件未找到错误）： 在尝试打开不存在的文件时引发的错误。
- ValueError（值错误）： 当函数接收到正确类型的参数，但参数值不合适时引发的错误。

这道题中 _ 与 flag 的值一致，因此我们只需要获取变量 _ 就可以获取 flag。

## KeyError
KeyError 出现在访问字典中不存在的键，利用时，可以随便构造一个字典，然后以需要读取的变量作为键名传进去。比如在这道题中输入：
```py
Give code: {"1":"2"}[_]
'flag{xxxx}'
```

## FileNotFoundError
FileNotFoundError 出现在找不到指定文件时，将需要读取的变量名传入文件操作函数就可以触发异常。例如 file(python2)、open 等。

但由于题目过滤了 e，这些函数都无法使用，如果需要测试的话可以将过滤的语句删除掉。
```py
Give code: open(_)
[Errno 2] No such file or directory: 'flag{xxxx}'
```

## ValueError
ValueError 比较好利用，只需要将需要读取的变量，传入一个函数，该函数的参数类型与这个要读取的变量不一致即可，例如：

```py
Give code: int(_)
ValueError: invalid literal for int() with base 10: 'flag{xxxx}'
```

当然这里过滤了 t，int 函数无法使用，可以去寻找一些别的函数。


# 参考
- [ctf-writeup/AmateursCTF 2023/Censorship at main · daffainfo/ctf-writeup](https://github.com/daffainfo/ctf-writeup/tree/main/AmateursCTF%202023/Censorship)