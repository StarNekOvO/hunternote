# 8x04 - Bug Bounty Guide

如何将研究成果转化为价值。

本章侧重"工程化交付"：如何把漏洞从研究阶段整理成可被厂商高效处理的报告与证据包。

## 1. 知名项目

### 1.1 主要平台

- **ASRP (Android Security Rewards Program)**: Google 官方项目，针对 Pixel 设备和 AOSP。
- **ZDI (Zero Day Initiative)**: 趋势科技旗下的漏洞收购平台，接受多厂商漏洞。
- **厂商私有项目**: 三星 (Samsung Mobile Security)、华为 (Huawei PSIRT)、小米 (Mi Security Center) 等。

### 1.2 项目要求对比

| 维度 | ASRP (Google) | Samsung Mobile Security | 华为 PSIRT | 小米安全中心 |
|------|---------------|------------------------|-----------|-------------|
| **范围** | Pixel 设备, AOSP, Android 内核 | Galaxy 系列, OneUI, Knox | 华为/荣耀设备, EMUI/HarmonyOS | 小米/红米设备, MIUI |
| **接受 Root 前置** | 否 (默认), 部分类别允许 | 否 | 否 | 否 |
| **要求补丁建议** | 推荐但非必需 | 推荐 | 推荐 | 非必需 |
| **要求根因分析** | 高危漏洞必需 | 必需 | 必需 | 推荐 |
| **响应时间 (首次)** | 1-2 工作日 | 3-5 工作日 | 5-7 工作日 | 3-5 工作日 |
| **修复窗口** | 90 天 | 90 天 | 90-180 天 | 90 天 |
| **重复判定** | 以内部追踪为准 | 以首次提交时间为准 | 以首次提交时间为准 | 以首次提交时间为准 |
| **支付方式** | 银行转账/捐赠 | 银行转账 | 银行转账 | 银行转账/礼品 |
| **提交入口** | bughunters.google.com | security.samsungmobile.com | isrc.huawei.com | sec.xiaomi.com |

补充：不同项目对"范围、影响、复现质量"的要求差异很大，提交前需先确认：

- 资产/版本是否在范围内
- 是否允许 root/工程机前置条件
- 是否要求提供补丁建议或根因分析

## 2. 奖励金额与定级标准

### 2.1 ASRP 奖励参考 (截至 2024)

| 漏洞类型 | 严重程度 | 基础奖励 | 带高质量报告 | 带 Exploit |
|---------|---------|---------|-------------|-----------|
| **远程代码执行 (RCE)** | Critical | $15,000 | $22,500 | $30,000+ |
| **本地提权到 Kernel** | Critical | $10,000 | $15,000 | $20,000+ |
| **沙箱逃逸** | Critical | $10,000 | $15,000 | $20,000+ |
| **Secure Element 攻击** | Critical | $50,000 | $75,000 | $100,000+ |
| **本地提权 (非 Kernel)** | High | $5,000 | $7,500 | $10,000 |
| **敏感数据泄露** | High | $3,000 | $4,500 | $6,000 |
| **拒绝服务 (永久)** | High | $2,000 | $3,000 | $4,000 |
| **信息泄露** | Medium | $1,000 | $1,500 | $2,000 |
| **拒绝服务 (临时)** | Low | $500 | $750 | $1,000 |

注意：
- "高质量报告" 包含完整根因分析和修复建议
- "带 Exploit" 指提供可工作的利用代码
- 组合漏洞链可获得额外奖励
- Pixel 专属漏洞有 50% 加成

### 2.2 严重程度定级标准

**Critical (严重)**
- 远程代码执行，无需用户交互
- 本地提权到 Kernel 或 TEE
- 绕过设备加密/安全启动
- 永久性设备接管

**High (高危)**
- 远程代码执行，需要用户交互
- 本地提权到 System/Root (非 Kernel)
- 敏感数据大规模泄露 (通讯录、短信、位置)
- 绕过锁屏或认证机制

**Medium (中危)**
- 跨应用数据访问
- 有限范围的信息泄露
- 需要特殊条件的提权

**Low (低危)**
- 需要物理访问的攻击
- 临时性拒绝服务
- 影响有限的信息泄露

### 2.3 影响奖励的因素

**加分项**
- 影响默认配置 (非需要用户手动开启的功能)
- 影响多个 Android 版本
- 提供完整利用链
- 代码质量高，易于理解
- 包含自动化测试脚本

**减分项**
- 需要 ADB 调试已开启
- 需要开发者选项/USB 调试
- 仅影响 Debug Build
- 需要安装恶意应用 (视具体场景)
- 复现步骤不清晰

## 3. 报告撰写

### 3.1 完整报告模板

```markdown
# 漏洞报告

## 基本信息
- **标题**: [组件名] - [漏洞类型] - [影响简述]
- **报告者**: [姓名/昵称]
- **报告日期**: [YYYY-MM-DD]
- **联系邮箱**: [email]

## 摘要
[一句话描述漏洞：什么组件，什么类型的漏洞，导致什么后果]

## 影响范围
- **受影响组件**: [包名/库名/驱动名]
- **受影响版本**: [Android 版本范围, 如 Android 12-14]
- **受影响设备**: [具体设备型号或"所有 AOSP 设备"]
- **Security Patch Level**: [如 2024-01-05 及之前]

## 严重程度评估
- **建议等级**: [Critical/High/Medium/Low]
- **CVSS 3.1 评分**: [评分] ([向量字符串])
- **评估依据**:
  - 攻击向量: [Network/Adjacent/Local/Physical]
  - 攻击复杂度: [Low/High]
  - 权限要求: [None/Low/High]
  - 用户交互: [None/Required]
  - 影响范围: [Unchanged/Changed]
  - 机密性影响: [None/Low/High]
  - 完整性影响: [None/Low/High]
  - 可用性影响: [None/Low/High]

## 复现环境
- **设备型号**: [如 Pixel 7 Pro]
- **Android 版本**: [如 Android 14]
- **Build 号**: [如 AP1A.240305.019.A1]
- **Kernel 版本**: [如 5.15.123-android14-8-xxxxx]
- **Security Patch Level**: [如 2024-03-05]
- **其他配置**: [如需要开启蓝牙/特定 App 版本等]

## 复现步骤
1. [步骤 1: 环境准备]
2. [步骤 2: 具体操作]
3. [步骤 3: ...]
4. [步骤 N: 观察结果]

**预期行为**: [正常情况应该发生什么]
**实际行为**: [漏洞触发后发生了什么]

## 证据材料
### 日志输出
```
[相关 logcat/dmesg 输出，标注关键行]
```

### 截图/录屏
[如有必要，附上截图或录屏链接]

### PoC 代码
```java
// 或其他语言
[可直接运行的最小 PoC]
```

## 根因分析
### 漏洞位置
- **文件**: [源码路径]
- **函数**: [函数名]
- **行号**: [行号范围]

### 问题代码
```java
// 存在问题的代码片段
[代码]
```

### 分析说明
[解释为什么这段代码存在漏洞，缺少了什么检查，或逻辑错误是什么]

## 修复建议
### 建议方案
```java
// 修复后的代码
[代码]
```

### 说明
[解释修复逻辑，以及为什么这样修复是安全的]

### 回归风险
[说明此修复可能影响的功能点，便于测试验证]

## 参考资料
- [相关 CVE/公告链接]
- [相关源码链接]
- [相关技术文档]

## 附件清单
- [ ] PoC 源码 (poc.zip)
- [ ] 复现视频 (repro.mp4)
- [ ] 完整日志 (logs.txt)
- [ ] 其他辅助文件
```

### 3.2 真实报告结构示例

以下是一个虚构但结构完整的报告示例：

```markdown
# 漏洞报告

## 基本信息
- **标题**: SystemUI - Intent Redirection - 任意 Activity 启动
- **报告者**: security_researcher
- **报告日期**: 2024-03-15
- **联系邮箱**: researcher@example.com

## 摘要
Android SystemUI 的 SlicePermissionActivity 存在 Intent Redirection 漏洞，
攻击者可通过构造恶意 Intent 以 System 权限启动任意未导出的 Activity，
导致敏感信息泄露或进一步提权。

## 影响范围
- **受影响组件**: com.android.systemui
- **受影响版本**: Android 12, 12L, 13, 14
- **受影响设备**: 所有使用原生 SystemUI 的设备
- **Security Patch Level**: 2024-03-05 及之前

## 严重程度评估
- **建议等级**: High
- **CVSS 3.1 评分**: 7.7 (CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
- **评估依据**:
  - 攻击向量: Local (需安装恶意应用)
  - 攻击复杂度: Low
  - 权限要求: None (恶意应用无需特殊权限)
  - 用户交互: None
  - 影响范围: Unchanged
  - 机密性影响: High (可访问受保护 Activity)
  - 完整性影响: High (可执行特权操作)
  - 可用性影响: None

## 复现环境
- **设备型号**: Pixel 7
- **Android 版本**: Android 14
- **Build 号**: AP1A.240305.019.A1
- **Kernel 版本**: 5.15.123-android14-8-00065-g53a132c79424
- **Security Patch Level**: 2024-03-05

## 复现步骤
1. 安装附件中的 PoC 应用 (poc.apk)
2. 打开 PoC 应用，点击 "Launch Attack" 按钮
3. 观察：Settings 应用的 ChooseLockGeneric Activity 被启动，
   该 Activity 通常只能由系统内部调用

**预期行为**: 系统应拒绝启动未导出的 Activity
**实际行为**: 未导出的 Activity 成功以 System 身份启动

## 证据材料
### 日志输出
```
03-15 10:23:45.123  1234  1234 I ActivityTaskManager: START u0 
{cmp=com.android.settings/.password.ChooseLockGeneric (has extras)} 
from uid 1000 // <-- 注意: uid 1000 (system) 而非恶意应用的 uid
```

### PoC 代码
```java
public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        Intent innerIntent = new Intent();
        innerIntent.setComponent(new ComponentName(
            "com.android.settings",
            "com.android.settings.password.ChooseLockGeneric"
        ));
        
        Intent outerIntent = new Intent();
        outerIntent.setComponent(new ComponentName(
            "com.android.systemui",
            "com.android.systemui.SlicePermissionActivity"
        ));
        outerIntent.putExtra("intent", innerIntent);
        
        startActivity(outerIntent);
    }
}
```

## 根因分析
### 漏洞位置
- **文件**: frameworks/base/packages/SystemUI/src/com/android/systemui/SlicePermissionActivity.java
- **函数**: onCreate()
- **行号**: 78-85

### 问题代码
```java
@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    Intent intent = getIntent();
    // 问题: 直接从 extras 获取 Intent 并启动，未做来源验证
    Intent launchIntent = intent.getParcelableExtra("intent");
    if (launchIntent != null) {
        startActivity(launchIntent);  // 以 System 权限启动
    }
}
```

### 分析说明
SlicePermissionActivity 运行在 system_server 进程 (UID 1000)，
直接提取并启动嵌套的 Intent 时，会以 System 身份执行。
攻击者可构造任意目标 Intent，突破组件导出限制。

## 修复建议
### 建议方案
```java
@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    Intent intent = getIntent();
    
    // 验证调用者
    int callingUid = Binder.getCallingUid();
    if (callingUid != Process.SYSTEM_UID && callingUid != Process.myUid()) {
        Log.e(TAG, "Unauthorized caller: " + callingUid);
        finish();
        return;
    }
    
    Intent launchIntent = intent.getParcelableExtra("intent");
    if (launchIntent != null) {
        // 限制只能启动同包内的 Activity
        ComponentName target = launchIntent.getComponent();
        if (target != null && !getPackageName().equals(target.getPackageName())) {
            Log.e(TAG, "Cross-package launch blocked");
            finish();
            return;
        }
        startActivity(launchIntent);
    }
}
```

### 说明
1. 添加调用者 UID 检查，仅允许系统进程调用
2. 限制启动目标必须为同包 Activity，防止跨包攻击
3. 两层防护确保即使绕过一层检查也无法利用

### 回归风险
- 需验证系统内部使用该 Activity 的流程是否正常
- 检查是否有合法的跨包启动场景

## 参考资料
- https://cwe.mitre.org/data/definitions/926.html (CWE-926)
- 类似漏洞: CVE-2020-0188, CVE-2021-0600

## 附件清单
- [x] PoC 源码 (poc.zip)
- [x] 复现视频 (repro.mp4)
- [x] 完整日志 (logs.txt)

---
假设分配 CVE: CVE-2024-XXXXX
假设修复版本: 2024-04 Security Patch
```

### 3.3 复现质量要点

- 固定环境（版本号、patch level、配置开关）
- 输入最小化（最小 Intent/最小样本/最小数据包）
- 给出失败/成功的判定标准（例如出现特定日志/崩溃）
- 避免使用不稳定的时序依赖

### 3.4 影响分析要点

- 触发条件：是否需要用户交互、是否需要本地权限
- 可达性：入口是否可由第三方应用或外部输入触发
- 缓解机制：SELinux/seccomp/进程拆分是否限制影响面

## 4. 报告写作技巧

### 4.1 标题撰写

**好的标题**
- `[BluetoothService] Heap Buffer Overflow in BNEP packet parsing leads to RCE`
- `[MediaCodec] Integer Overflow in AVC decoder allows sandbox escape`
- `[Settings] Exported Activity allows bypass of screen lock`

**差的标题**
- `Found a bug in Android`
- `Critical vulnerability!!!`
- `Bluetooth crash`

### 4.2 摘要撰写原则

1. **完整性**: 包含组件、漏洞类型、影响
2. **简洁性**: 控制在 2-3 句话
3. **准确性**: 不夸大影响范围

示例:
> SystemUI 的 SlicePermissionActivity 存在 Intent Redirection 漏洞。
> 攻击者可通过构造恶意 Intent，以 System 权限启动任意未导出的 Activity。
> 这可能导致绑定服务访问、敏感数据读取或进一步提权。

### 4.3 复现步骤撰写

**原则**
- 每步只做一件事
- 包含预期结果和实际结果
- 提供可验证的判定条件

**示例**
```
1. 将设备恢复出厂设置，确保干净环境
2. 完成初始设置，不登录任何账户
3. 安装 PoC 应用: adb install poc.apk
4. 运行: adb shell am start -n com.poc/.MainActivity
5. 观察 logcat: adb logcat -s ActivityTaskManager
   
预期: 应显示 "Permission Denied" 错误
实际: Activity 成功启动，日志显示 "START u0 {...} from uid 1000"
```

### 4.4 常见错误与避免方法

| 错误类型 | 具体表现 | 正确做法 |
|---------|---------|---------|
| **环境不明确** | "在某些 Android 版本上有效" | 列出精确版本号、Build 号、Patch Level |
| **步骤不可复现** | "执行 PoC 脚本" 但脚本依赖未说明 | 列出所有依赖项和环境配置 |
| **影响夸大** | "可以黑掉任何 Android 手机" | 明确攻击前置条件和实际影响范围 |
| **缺少证据** | 只有文字描述，无日志/截图 | 附上关键日志、堆栈、录屏 |
| **PoC 过于复杂** | 几百行代码，混合无关功能 | 提供最小可复现代码 |
| **未说明失败条件** | 只说"会崩溃" | 说明什么情况下成功/失败 |
| **忽略缓解措施** | 未提及 SELinux 等防护 | 分析缓解机制是否影响利用 |
| **根因分析模糊** | "代码有问题" | 指出具体文件、函数、行号 |
| **修复建议不当** | 建议"重写整个模块" | 提供最小化、可验证的修复方案 |

### 4.5 提升报告质量的技巧

**技巧 1: 使用 diff 格式展示修复**
```diff
- if (intent != null) {
-     startActivity(intent);
- }
+ if (intent != null && isValidTarget(intent)) {
+     startActivity(intent);
+ }
```

**技巧 2: 提供多版本测试结果**
| Android 版本 | Patch Level | 是否受影响 |
|-------------|-------------|-----------|
| Android 12 | 2024-01-05 | Yes |
| Android 13 | 2024-01-05 | Yes |
| Android 14 | 2024-01-05 | Yes |
| Android 14 | 2024-04-05 | No (已修复) |

**技巧 3: 画出攻击流程图**
```
恶意应用 --> SystemUI (system) --> 目标 Activity
   |              |                      |
   |-- send ------+---- launch ----------+
   |  Intent      |  with system uid     |
```

**技巧 4: 关联已知漏洞**
如果你的发现与已知 CVE 类似或是变体，引用它们可以帮助评审者快速理解：
> 此漏洞与 CVE-2020-0188 属于同类问题 (Intent Redirection)，
> 但影响不同组件 (SystemUI vs Settings)。

**技巧 5: 准备 FAQ**
预判评审者可能的疑问并提前解答：
- Q: 为什么不需要特殊权限？
- A: SlicePermissionActivity 是导出的，任何应用都可启动。
- Q: SELinux 是否能阻止？
- A: 不能，SystemUI 域有足够权限启动 Settings Activity。

## 5. 时间线与合规

### 5.1 标准披露时间线

```
Day 0:   发现漏洞
Day 1:   首次报告提交
Day 1-7: 厂商确认收到并开始分析
Day 7-30: 厂商确认有效性，分配追踪号
Day 30-90: 修复开发与测试
Day 90:  修复发布 (或协商延期)
Day 90+: 公开披露 (如果允许)
```

### 5.2 常见实践

- 与厂商沟通修复窗口
- 在修复发布前避免公开可复现细节
- 保留复现证据与版本信息用于后续确认
- 定期跟进修复进度 (每 30 天)
- 保存所有通信记录

### 5.3 负责任披露原则

1. **优先通知厂商**: 给予合理的修复时间
2. **保护用户**: 不公开未修复漏洞的利用细节
3. **透明沟通**: 与厂商保持沟通渠道畅通
4. **尊重约定**: 遵守 NDA 或协议中的披露条款
5. **准确报告**: 不夸大漏洞影响

## 参考资源

**官方文档**
- https://source.android.com/docs/setup/contribute/report-bugs — AOSP 官方问题提交流程
- https://source.android.com/docs/security/bulletin — 安全公告入口
- https://bughunters.google.com/about/rules/6625378258649088/android-and-google-devices-security-reward-program-rules — ASRP 规则

**漏洞数据库**
- https://www.cvedetails.com/vendor/1224/Google.html — Google CVE 列表
- https://android.googlesource.com/platform/frameworks/base/+log — AOSP 提交历史

**学习资源**
- https://github.blog/2020-05-06-how-to-write-good-bug-reports/ — 如何写好漏洞报告
