# Java Essentials for Android Development

Java 语言教程，为 Android Framework 和应用开发打基础。

## 为什么学 Java

| Android 组件 | 语言 | 示例 |
|-------------|------|------|
| Framework | Java/Kotlin | AMS, PMS, WMS |
| System Services | Java | system_server |
| App 开发 | Java/Kotlin | Activity, Service |
| AIDL | Java | Binder 接口 |

## 目录

- [00 - 基础语法](./00-basics.md)
- [01 - 面向对象](./01-oop.md)
- [02 - 集合框架](./02-collections.md)
- [03 - 并发编程](./03-concurrency.md)
- [04 - JVM 与 ART](./04-jvm-art.md)
- [05 - Smali 与逆向](./05-smali.md)
- [06 - AOSP 实战](./06-android-java.md)
- [07 - Xposed/LSPosed](./07-xposed-lsposed.md)

## 相关 CVE (2023-2025)

| CVE | 组件 | 类型 |
|-----|------|------|
| CVE-2023-21089 | AMS | 后台服务保活 (LPE) |
| CVE-2023-21292 | AMS | confused deputy |
| CVE-2023-21273 | System | RCE (Critical) |
| CVE-2024-0025 | AMS | 后台启动绕过 |
| CVE-2024-0044 | PMS | run-as any app |
| CVE-2024-43093 | ExtStorage | 路径绕过 (野外利用) |
| CVE-2025-48543 | ART | UAF 沙箱逃逸 |
| CVE-2025-48593 | System | Zero-click RCE |
| CVE-2025-48633 | Framework | Binder 身份伪造 |
