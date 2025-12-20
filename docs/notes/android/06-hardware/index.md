# Part 6: Hardware Security
硬件是 Android 设备的基础，现代手机集成了众多复杂的硬件组件（如基带、Wi-Fi、蓝牙、传感器等）。这些组件通常运行专有固件，并通过驱动与 Android 系统交互。硬件相关的漏洞可能导致严重的安全风险，如远程代码执行、隐私泄露等。

## 参考（AOSP）
- https://source.android.com/docs/security/features — Android 安全功能总览入口（含 TEE/Keystore/Verified Boot）。
- https://source.android.com/docs/security/features/verifiedboot — Verified Boot/AVB 的官方入口。
