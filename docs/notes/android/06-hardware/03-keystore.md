# 6x03 - Hardware-backed Keystore

Android Keystore 允许应用在硬件中生成和存储密钥。

Keystore 的核心安全承诺是：

- 密钥材料不以明文形式暴露给普通用户态进程
- 加解密等关键操作在受保护环境内完成（TEE 或安全芯片）
- 可对外提供"可验证的证明"（attestation）

## 1. 架构概述

### 1.1 Keystore 架构演进

```
┌─────────────────────────────────────────────────────────────────┐
│                         应用层                                   │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │              Android KeyStore API                            ││
│  │         (java.security.KeyStore)                            ││
│  └──────────────────────────┬──────────────────────────────────┘│
└─────────────────────────────┼───────────────────────────────────┘
                              │ Binder IPC
┌─────────────────────────────▼───────────────────────────────────┐
│                       系统服务层                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │              keystore2 服务                                  ││
│  │         (Android 12+, Rust 实现)                            ││
│  │                                                              ││
│  │  职责: 密钥访问控制, 数据库管理, 加密 blob 存储               ││
│  └──────────────────────────┬──────────────────────────────────┘│
└─────────────────────────────┼───────────────────────────────────┘
                              │ HIDL/AIDL
┌─────────────────────────────▼───────────────────────────────────┐
│                        HAL 层                                    │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │              KeyMint HAL (Android 12+)                       ││
│  │              或 Keymaster HAL (旧版)                         ││
│  └──────────────────────────┬──────────────────────────────────┘│
└─────────────────────────────┼───────────────────────────────────┘
                              │ TEE 通信 (SMC/共享内存)
┌─────────────────────────────▼───────────────────────────────────┐
│                        安全环境                                   │
│  ┌─────────────────────┐  ┌────────────────────────────────────┐│
│  │   TEE (TrustZone)   │  │      StrongBox (安全芯片)          ││
│  │   - OP-TEE TA       │  │      - 独立 MCU                    ││
│  │   - QSEE TA         │  │      - 物理隔离                    ││
│  │   - Trusty TA       │  │      - 抗物理攻击                  ││
│  └─────────────────────┘  └────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Keymaster vs KeyMint

| 特性 | Keymaster (≤Android 11) | KeyMint (≥Android 12) |
|------|------------------------|----------------------|
| 接口 | HIDL | AIDL (Stable AIDL) |
| 版本 | 4.0, 4.1 | 1.0, 2.0, 3.0 |
| 新功能 | - | ECDH, 曲线25519, 密钥升级 |
| 实现语言 | C++ | Rust (HAL 层可选) |

### 1.3 密钥存储结构

```c
// 密钥 Blob 结构 (概念模型)
struct keymaster_key_blob {
    // 版本与算法信息
    uint32_t key_material_version;
    keymaster_algorithm_t algorithm;
    
    // 加密的密钥材料
    // 使用 Hardware Root Key (HRK) 派生的 KEK 加密
    encrypted_key_material_t material;
    
    // 密钥特性 (认证数据)
    keymaster_key_param_set_t hw_enforced;  // 硬件强制执行
    keymaster_key_param_set_t sw_enforced;  // 软件强制执行
    
    // HMAC 完整性保护
    uint8_t hmac[32];
};

// 密钥永远不以明文形式离开 TEE/StrongBox
// 应用只获得加密的 blob，解密密钥在硬件内部
```

## 2. 密钥认证 (Key Attestation)

### 2.1 认证流程

```
应用                    Keystore               TEE/StrongBox
  │                        │                        │
  │ 1. 生成密钥 + 认证请求  │                        │
  │    (附带 challenge)    │                        │
  │───────────────────────>│                        │
  │                        │ 2. 转发到安全环境        │
  │                        │───────────────────────>│
  │                        │                        │
  │                        │      3. 生成密钥        │
  │                        │      4. 生成认证链      │
  │                        │         - 设备状态      │
  │                        │         - 启动状态      │
  │                        │         - 密钥属性      │
  │                        │<───────────────────────│
  │<───────────────────────│                        │
  │ 5. 返回证书链           │                        │
  │                        │                        │
  │ 6. 发送到服务器验证     │                        │
  │─────────────────────────────────────────────────>
```

### 2.2 证书链结构

```
Google Root CA
    │
    ▼
Google Intermediate CA
    │
    ▼
Device Attestation Key (厂商预置)
    │
    ▼
Key Attestation Certificate (每个密钥生成)
    │
    包含:
    ├── 密钥属性 (算法、用途、用户认证要求)
    ├── 设备信息
    │   ├── attestationSecurityLevel (SOFTWARE/TEE/STRONGBOX)
    │   ├── verifiedBootState (Verified/SelfSigned/Unverified/Failed)
    │   ├── deviceLocked (true/false)
    │   └── osVersion, osPatchLevel
    └── challenge (防重放)
```

### 2.3 Attestation Extension 解析

```java
// ASN.1 结构 (简化)
KeyDescription ::= SEQUENCE {
    attestationVersion  INTEGER,
    attestationSecurityLevel  SecurityLevel,
    keymasterVersion  INTEGER,
    keymasterSecurityLevel  SecurityLevel,
    attestationChallenge  OCTET STRING,
    uniqueId  OCTET STRING,
    softwareEnforced  AuthorizationList,
    teeEnforced  AuthorizationList,
}

// SecurityLevel 枚举
SecurityLevel ::= ENUMERATED {
    Software  (0),     // 纯软件实现，最弱
    TrustedEnvironment  (1),  // TEE，中等
    StrongBox  (2),    // 安全芯片，最强
}
```

**解析示例**：
```java
// Java 代码解析 attestation 证书
import android.security.keystore.KeyGenParameterSpec;
import java.security.cert.X509Certificate;

// 生成带 attestation 的密钥
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
    "key_alias",
    KeyProperties.PURPOSE_SIGN)
    .setAttestationChallenge(challenge)  // 服务器提供的随机数
    .setDigests(KeyProperties.DIGEST_SHA256)
    .build();

// 获取证书链
Certificate[] chain = keyStore.getCertificateChain("key_alias");
X509Certificate attestationCert = (X509Certificate) chain[0];

// 解析 attestation extension (OID: 1.3.6.1.4.1.11129.2.1.17)
byte[] extensionData = attestationCert.getExtensionValue(
    "1.3.6.1.4.1.11129.2.1.17");
// 使用 ASN.1 解析库解析具体字段
```

## 3. 安全机制

### 3.1 用户认证绑定

```java
// 生成需要用户认证的密钥
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
    "auth_bound_key",
    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
    .setDigests(KeyProperties.DIGEST_SHA256)
    // 认证绑定配置
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationValidityDurationSeconds(30)  // 30秒内有效
    // 或者
    .setUserAuthenticationParameters(
        0,  // 每次使用都需认证
        KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL)
    .setInvalidatedByBiometricEnrollment(true)  // 新增指纹时失效
    .build();

// 使用密钥前需要先通过 BiometricPrompt 认证
```

**认证绑定类型**：

| 类型 | 描述 | 安全级别 |
|------|------|----------|
| 无绑定 | 任何时候都可使用 | 低 |
| 时间窗口 | 认证后 N 秒内可用 | 中 |
| 每次使用 | 每次操作都需认证 | 高 |
| 解锁状态 | 设备解锁时可用 | 中 |

### 3.2 绑定与限制

```java
// 其他密钥限制
KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(...)
    // 用途限制
    .setKeyValidityStart(startDate)
    .setKeyValidityEnd(endDate)
    
    // 加密操作限制
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    
    // 密钥不可导出 (默认)
    // 无法调用 getKey() 获取原始密钥材料
    
    // 绑定到安全硬件
    .setIsStrongBoxBacked(true)  // 要求 StrongBox
    
    // 防回滚
    .setMaxUsageCount(10);  // 最多使用 10 次
```

## 4. 攻击面与漏洞

### 4.1 历史漏洞

**[CVE-2024-29779](../../../cves/entries/CVE-2024-29779.md): KeyMint 设备保护绕过**
```
漏洞类型: 逻辑漏洞
影响: 绕过设备保护机制

攻击场景:
1. 攻击者找到 KeyMint 服务中的边界检查漏洞
2. 绕过正常的访问控制检查
3. 可能导致未授权的密钥操作

修复: 2024 安全补丁更新
```

**[CVE-2025-20655](../../../cves/entries/CVE-2025-20655.md): Keymaster 越界读取**
```
漏洞类型: OOB Read
影响: 信息泄露

攻击原理:
- Keymaster 服务在处理某些请求时
- 未正确验证输入长度
- 可能读取敏感内存区域

修复: 2025 年 4 月安全更新
```

**[CVE-2024-45445](../../../cves/entries/CVE-2024-45445.md): Keystore 资源泄露**
```
漏洞类型: 资源耗尽
影响: 拒绝服务

攻击原理:
- Keystore 模块未正确释放资源
- 重复触发可导致系统不稳定
```

### 4.2 攻击向量分析

```
┌─────────────────────────────────────────────────────────────────┐
│                     Keystore 攻击面                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. 应用层攻击                                                   │
│     ├── Keystore API 滥用 (权限/参数)                           │
│     ├── 应用漏洞导致密钥泄露                                     │
│     └── 时序攻击推断密钥属性                                     │
│                                                                 │
│  2. 系统服务层攻击                                               │
│     ├── keystore2 服务漏洞 (Binder 接口)                        │
│     ├── SELinux 策略绕过                                        │
│     └── 数据库/Blob 存储漏洞                                    │
│                                                                 │
│  3. HAL 层攻击                                                   │
│     ├── KeyMint HAL 实现漏洞                                    │
│     ├── AIDL 解析漏洞                                           │
│     └── 共享内存处理问题                                         │
│                                                                 │
│  4. TEE 攻击                                                     │
│     ├── Trustlet 漏洞 (见 TrustZone 章节)                       │
│     ├── TEE OS 漏洞                                             │
│     └── 硬件侧信道                                               │
│                                                                 │
│  5. 物理攻击 (针对 StrongBox)                                    │
│     ├── 故障注入                                                 │
│     ├── 功耗分析                                                 │
│     └── 电磁分析                                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 4.3 常见漏洞模式

**认证绕过**：
```java
// 漏洞: 认证检查在软件层而非硬件层
// 如果 HAL 实现有问题，可能绕过认证要求

// 攻击者研究方向:
// 1. 检查 hw_enforced vs sw_enforced 的差异
// 2. 认证状态的传递是否完整
// 3. 时间窗口的实现是否安全
```

**Attestation 伪造**：
```java
// 攻击目标: 伪造或修改 attestation 证书链
// 目的: 欺骗服务器，使其信任不安全的设备

// 研究方向:
// 1. 设备证书密钥是否可提取
// 2. attestation 生成过程是否有漏洞
// 3. 验证方是否正确检查整个证书链
```

**密钥材料泄露**：
```c
// 漏洞模式: 内存处理不当

// 示例: 未清零临时缓冲区
void process_key(key_blob_t *blob) {
    uint8_t temp_key[32];
    decrypt_key(blob, temp_key);
    use_key(temp_key);
    // 漏洞: 未清零 temp_key
    // return;  // temp_key 残留在栈上
    
    // 正确做法:
    memset_s(temp_key, sizeof(temp_key), 0, sizeof(temp_key));
}
```

## 5. 安全研究方法

### 5.1 检查设备 Keystore 能力

```bash
# 检查支持的算法和安全级别
adb shell dumpsys keystore2 | grep -E "SecurityLevel|Algorithm"

# 检查 KeyMint 版本
adb shell service list | grep keymint
adb shell getprop ro.hardware.keystore

# 检查 StrongBox 支持
adb shell pm has-feature android.hardware.strongbox_keystore

# 查看 Keystore 错误日志
adb logcat -s keystore2 keymint keymaster
```

### 5.2 Frida Hook 示例

```javascript
// Hook KeyStore API 监控密钥操作
Java.perform(function() {
    var KeyStore = Java.use("java.security.KeyStore");
    
    KeyStore.getEntry.overload(
        'java.lang.String', 
        'java.security.KeyStore$ProtectionParameter'
    ).implementation = function(alias, param) {
        console.log("[KeyStore] getEntry called: " + alias);
        var result = this.getEntry(alias, param);
        console.log("[KeyStore] Entry type: " + result.getClass().getName());
        return result;
    };
    
    // Hook KeyGenParameterSpec 查看密钥生成参数
    var KeyGenParameterSpec = Java.use(
        "android.security.keystore.KeyGenParameterSpec");
    var Builder = Java.use(
        "android.security.keystore.KeyGenParameterSpec$Builder");
    
    Builder.build.implementation = function() {
        console.log("[KeyGen] Building KeyGenParameterSpec");
        console.log("  Alias: " + this.mKeystoreAlias.value);
        console.log("  Purposes: " + this.mPurposes.value);
        console.log("  UserAuthRequired: " + this.mUserAuthenticationRequired.value);
        return this.build();
    };
});
```

### 5.3 审计 Checklist

| 检查项 | 问题 | 风险级别 |
|--------|------|----------|
| 安全级别 | 密钥是否真的硬件支持？可能是软件实现 | 高 |
| 认证绑定 | 敏感密钥是否要求用户认证？ | 高 |
| 证书验证 | Attestation 是否正确验证完整链？ | 高 |
| 算法选择 | 是否使用已知弱算法？ | 中 |
| 错误处理 | 错误信息是否泄露敏感状态？ | 中 |
| 密钥有效期 | 是否设置合理的过期时间？ | 低 |
| 用途限制 | PURPOSE 是否最小化？ | 低 |

## 6. 实际案例

### 6.1 正确的密钥使用模式

```java
// 用于设备绑定认证的密钥
public class SecureKeyManager {
    private static final String KEY_ALIAS = "device_auth_key";
    
    public void generateKey(byte[] challenge) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        
        kpg.initialize(new KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN)
            // 强制使用 TEE 或 StrongBox
            .setIsStrongBoxBacked(true)  // 优先 StrongBox
            // 用户认证绑定
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(
                0,  // 每次使用需要认证
                KeyProperties.AUTH_BIOMETRIC_STRONG)
            // 算法配置
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAlgorithmParameterSpec(
                new ECGenParameterSpec("secp256r1"))
            // Attestation
            .setAttestationChallenge(challenge)
            .build());
        
        KeyPair kp = kpg.generateKeyPair();
    }
    
    public byte[] sign(byte[] data) throws Exception {
        // 需要先通过 BiometricPrompt 认证
        BiometricPrompt.CryptoObject cryptoObject = 
            new BiometricPrompt.CryptoObject(getSignature());
        
        // ... 显示认证对话框 ...
        
        // 认证成功后签名
        Signature sig = Signature.getInstance("SHA256withECDSA");
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        sig.initSign((PrivateKey) ks.getKey(KEY_ALIAS, null));
        sig.update(data);
        return sig.sign();
    }
}
```

### 6.2 服务端 Attestation 验证

```python
# Python 服务端验证 attestation 证书链
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def verify_attestation(cert_chain_pem, challenge):
    """验证 Android Key Attestation"""
    
    # 解析证书链
    certs = []
    for cert_pem in cert_chain_pem:
        cert = x509.load_pem_x509_certificate(
            cert_pem.encode(), default_backend())
        certs.append(cert)
    
    # 验证链完整性
    # 1. 验证签名链
    # 2. 验证根证书是 Google Root
    
    # 解析 Attestation Extension
    attestation_cert = certs[0]
    ext = attestation_cert.extensions.get_extension_for_oid(
        x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"))
    
    # 解析 ASN.1 结构
    attestation = parse_key_description(ext.value.value)
    
    # 关键检查
    checks = {
        # 检查 challenge 匹配
        "challenge_match": attestation.challenge == challenge,
        # 检查是否硬件支持
        "hw_backed": attestation.attestation_security_level >= 1,
        # 检查设备状态
        "device_locked": attestation.tee_enforced.get("deviceLocked", False),
        "verified_boot": attestation.tee_enforced.get("verifiedBootState") == "Verified",
        # 检查 OS 补丁级别
        "patch_level": attestation.tee_enforced.get("osPatchLevel", 0) >= MIN_PATCH,
    }
    
    return all(checks.values()), checks
```

## 7. 参考资源

### 官方文档
- [Android Keystore System](https://developer.android.com/privacy-and-security/keystore)
- [Key Attestation](https://source.android.com/docs/security/features/keystore/attestation)
- [KeyMint HAL](https://android.googlesource.com/platform/hardware/interfaces/+/master/security/)

### 安全公告
- [Android Security Bulletin](https://source.android.com/docs/security/bulletin)
- [CVE-2024-29779 Advisory](https://vulert.com/vuln-db/android-platform-system-keymint-174814)

### 研究资源
- [Google Key Attestation Root Certificates](https://developer.android.com/training/articles/security-key-attestation#root-certificates)
- [Keymaster/KeyMint TA Security Research](https://googleprojectzero.blogspot.com/)
