# Android Internals

Android 系统核心架构与底层运行机制, 从 Userland 到 Kernel 边界

## Java Framework & System Services
系统启动流程 (Init -> Zygote -> SystemServer)、核心服务管理 (AMS, WMS)、消息循环 (Handler/Looper)

## Native Runtime & IPC
Binder 机制全解 (驱动交互/各种映射)、Parcel 数据结构、ART 虚拟机、ELF 文件格式与 Linker 动态链接

## Kernel Interfaces & HAL
硬件抽象层 (HAL) 原理、以及 Android 特有的内核机制：Ashmem (匿名共享内存)、LowMemoryKiller、Binder Driver 实现原理