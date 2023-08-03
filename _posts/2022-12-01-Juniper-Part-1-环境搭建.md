---
title: Juniper Part 1 - Basic Environment
date: 2022-12-01 20:36:46
categories:
- IOT
tags:
- Juniper
toc: true
# notshow: true
---


# Download

1. Official download link：

    1. [vSRX 3.0](https://support.juniper.net/support/downloads/?p=vsrx-evaluation)

2. Others：

    vMX链接：https://i.srijit.com/2wZce6x  
    vSRX链接：https://i.srijit.com/2VSV56S  
    Version and file details –

    > vMX –  
    > 👉 For ESXi environment – vmx-bundle-esxi-18.2R1.9.tgz  
    > 👉 For KVM environment (also for use with GNS3) – vmx-bundle-18.2R1.9.tgz  
    > 👉 Trial License for 60 days
    >
    > vSRX –  
    > 👉 junos-vsrx3-x86-64-19.2R1.8.qcow2  
    > 👉 junos-vsrx3-x86-64-19.2R1.8.ide.ova  
    > 👉 junos-vsrx3-x86-64-20.1R1.11.qcow2  
    > 👉 junos-vsrx3-x86-64-20.1R1.11.ide.ova  
    > 👉 junos-media-vsrx-x86-64-vmdisk-20.1R1.11.qcow2  
    > 👉 junos-media-vsrx-x86-64-vmdisk-20.1R1.11.ide.ova  
    > 👉 Trial License for 60 days
    >
3. 百度网盘链接：[https://pan.baidu.com/s/1uLT2BopSzvU7tzMTRxTs7w](https://pan.baidu.com/s/1uLT2BopSzvU7tzMTRxTs7w) 提取码：e5tk

    > Description Release File Date File Size
    >
    > * vSRX Hyper V Image 20.3R1, 05 Oct 2020，vhd (1718.46MB)
    > * vSRX KVM Appliance 20.3R1, 05 Oct 2020，qcow2 (885.56MB)
    > * vSRX VMware Appliance with IDE virtual disk (.ova) 20.3R1, 05 Oct 2020，ova (887.51MB)
    > * vSRX VMware Appliance with SCSI virtual disk (.ova) 20.3R1, 05 Oct 2020，ova (887.51MB)
    >
4. junos-vsrx-12.1X44-D10.4-domestic.ova 下载地址

    链接：[http://pan.baidu.com/s/1eQy3O2Y](http://pan.baidu.com/s/1eQy3O2Y)  
    密码：ig8e

    解压密码：[www.santongit.com](http://www.santongit.com/)

‍

# Install

[手把手教你安装Juniper 模拟器](https://blog.csdn.net/weixin_44309905/article/details/122777900)

‍

# Configuration

Common Juniper commands:

- show xxxx: View configurations under the xxxx menu
- edit xxx: Enter the xxx menu
- set xxx: Add configurations
- commit: Save configurations
- delete: Delete configurations
- up: Return to the previous menu
- top: Return to the top-level menu

## Setting the root password

Log in as the root user with an initial blank password, and enter the system CLI. Then, enter the configuration mode and set the root password.

```shell
root@% 				// Initially enters the command line of the system, similar to a Unix system
root@% cli 			// Enter the firewall maintenance and configuration interface by typing "cli" and pressing enter
root> 				// When the prompt is ">", it means you have entered the general mode of the firewall
root> configure 		// Enter the configuration mode by typing "configure" in general mode
root# 				// When the prompt is "#", it means you have entered the configuration mode of the firewall
root# set system root-authentication plain-text-password
New password:
Retype new password:

root# commit
commit complete
root# commit 			// You need to submit twice for the changes to take effect. If you only commit once, the configuration will roll back after 2 minutes.
commit complete
root#
```

## Setting the addresses of the internal and external network ports

* Use ge-0/0/0.0 as the WAN port for connecting to the internet
* Use ge-0/0/1.0 as the LAN port for the internal network

```shell
root# edit interfaces

[edit interfaces]
root# set ge-0/0/0/0.0 family inet addr 210.1.1.2/24

[edit interfaces]
root# set ge-0/0/0/1.0 family inet addr 10.0.0.1/24
```

After completing the configuration, you can use the "show" command to view the current configuration.

If there are any errors in the configuration, you can delete the configuration using the "delete" command, which replaces "set".


```shell
[edit interfaces]
root# delete ge-0/0/0/1.0 family inet addr 10.0.0.1/24
```

‍

## Adding a default route

To add a default route, use the following command:

```shell
root# edit routing-options static

[edit routing-options static]
root# set route 0.0.0.0/0 next-hop 210.1.1.1
```

## Placing the internal and external network ports in different zones

To place the internal and external network ports in different zones, use the following commands:

```shell
root# edit security zones security-zone trust

[edit security zones security-zone trust]
root# set interfaces ge-0/0/1.0

[edit security zones security-zone trust]
root# set host-inbound-traffic system-services all

[edit security zones security-zone trust]
root# set host-inbound-traffic protocols all
```

配置完之后可以使用 show 进行查看。

配置外网口，仅开放 ping

```shell
root# edit security zones security-zone untrust

[edit security zones security-zone untrust]
root# set interfaces ge-0/0/0.0

[edit security zones security-zone untrust]
root# set host-inbound-traffic system-services ping
```

‍
## Configuring source IP-based NAT translation

- To configure a source IP-based NAT translation, create a rule named "Trust_to_Untrust_NAT" with the appropriate "from" and "to" settings.

- Create a default NAT rule that applies to any internal IP address that needs to access the WAN.

```shell
root# edit security nat source

[edit security nat source]
root# edit rule-set Trust_to_Untrust_NAT

[edit security nat source rule-set Trust_to_Untrust_NAT]
root# set from zone trust

[edit security nat source rule-set Trust_to_Untrust_NAT]
root# set to zone untrust

[edit security nat source rule-set Trust_to_Untrust_NAT]
root# edit rule Default_NAT

[edit security nat source rule-set Trust_to_Untrust_NAT rule Default_NAT]
root# set match source-address 0.0.0.0/0

[edit security nat source rule-set Trust_to_Untrust_NAT rule Default_NAT]
root# set then source-nat interface
```

## Creating a policy to allow traffic from the internal network to the external network

Create a policy that matches any destination address, source address, and application, and allows traffic to pass through.


```shell
root# edit security policies from-zone trust to-zone untrust

[security policies from-zone trust to-zone untrust]
root# edit policies Default-Permit

[security policies from-zone trust to-zone untrust policies Default-Permit]
root# set match source-address any

[security policies from-zone trust to-zone untrust policies Default-Permit]
root# set match destination-address any

[security policies from-zone trust to-zone untrust policies Default-Permit]
root# set match application any

[security policies from-zone trust to-zone untrust policies Default-Permit]
root# set then permit
```

## Enable SSH and Telnet services

```shell
root# edit system services
root# set ssh
root# set telnet
root# set ssh root login allow
root# set telnet connection-limit 5
```

‍

## Enable web management interface


```shell
root# set web-management https system-generated-certificate

root# set web-management https interface ge-0/0/1.0 port 8899
```

‍

‍

‍

# References

* [Juniper SRX 防火墙并没有你想象那么难](https://www.bilibili.com/video/BV1oN411d7Mr/?spm_id_from=333.337.search-card.all.click&vd_source=98e452de67ccb8e0774ac1b8f6914de5)

‍

‍
