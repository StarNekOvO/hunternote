# 3x03 - WindowManagerService (WMS)

WMS 负责管理屏幕上的所有窗口及其显示顺序。

它是 UI 安全研究绕不开的一层：窗口的层级、可见性、触摸事件归属、截屏/录屏保护、Overlay 限制，很多都在 WMS/输入系统的协作里完成。

## 1. 核心架构

### 1.1 WMS 在系统中的位置

```
┌─────────────────────────────────────────────────────────────────┐
│                         应用层                                   │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  Activity → Window → DecorView → ViewRootImpl              ││
│  └──────────────────────────┬──────────────────────────────────┘│
└─────────────────────────────┼───────────────────────────────────┘
                              │ Binder (IWindowSession)
┌─────────────────────────────▼───────────────────────────────────┐
│                     Framework 服务层                             │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │              WindowManagerService (WMS)                     ││
│  │  - 窗口状态管理 (WindowState)                                ││
│  │  - 窗口层级计算 (WindowContainer hierarchy)                  ││
│  │  - 焦点计算与分配                                            ││
│  │  - 动画协调                                                  ││
│  └──────────────────────────┬──────────────────────────────────┘│
│  ┌──────────────────────────┼──────────────────────────────────┐│
│  │  InputManagerService     │    ActivityTaskManagerService    ││
│  │  (输入事件分发)           │    (任务/Activity 状态)          ││
│  └──────────────────────────┼──────────────────────────────────┘│
└─────────────────────────────┼───────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│                        Native 层                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    SurfaceFlinger                           ││
│  │  - Layer 合成                                                ││
│  │  - 硬件 Composer 交互                                        ││
│  │  - VSync 同步                                                ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 窗口类型与层级

```java
// WindowManager.LayoutParams 中定义的窗口类型
public static final int TYPE_BASE_APPLICATION     = 1;    // Activity 窗口
public static final int TYPE_APPLICATION          = 2;    // 普通应用窗口
public static final int TYPE_APPLICATION_PANEL    = 1000; // 子面板
public static final int TYPE_APPLICATION_OVERLAY  = 2038; // 应用 Overlay

// 系统窗口类型 (需要系统权限)
public static final int TYPE_STATUS_BAR           = 2000; // 状态栏
public static final int TYPE_NAVIGATION_BAR       = 2019; // 导航栏
public static final int TYPE_INPUT_METHOD         = 2011; // 输入法
public static final int TYPE_KEYGUARD_DIALOG      = 2009; // 锁屏对话框
public static final int TYPE_TOAST                = 2005; // Toast

// 层级数值越大，显示越靠前
// 安全研究关注：哪些类型可以覆盖敏感窗口
```

**窗口层级可视化**：
```
Z-order (从底到顶):
┌─────────────────────────────────────┐
│ TYPE_APPLICATION_OVERLAY (2038)     │  ← Overlay 攻击关注点
├─────────────────────────────────────┤
│ TYPE_INPUT_METHOD (2011)            │
├─────────────────────────────────────┤
│ TYPE_STATUS_BAR (2000)              │
├─────────────────────────────────────┤
│ TYPE_APPLICATION (2)                │  ← 普通应用
├─────────────────────────────────────┤
│ Wallpaper                           │
└─────────────────────────────────────┘
```

## 2. 输入事件分发

### 2.1 输入路径

```
内核设备 (/dev/input/eventX)
       │
       ▼
InputReader (native)
- 读取原始事件
- 事件预处理
       │
       ▼
InputDispatcher (native)
- 找到目标窗口
- 权限检查
- 事件队列管理
       │
       ▼
InputManagerService (Java)
- 策略决策
- 与 WMS 协调焦点
       │
       ▼
应用进程 InputChannel
- ViewRootImpl 接收
- 分发到 View 树
```

### 2.2 输入焦点与窗口焦点

```java
// WMS 中的焦点计算
// frameworks/base/services/core/java/com/android/server/wm/

// 输入焦点窗口
WindowState mInputMethodTarget;  // 当前接收输入法的窗口
WindowState mFocusedWindow;      // 当前焦点窗口

// 焦点计算时的安全考量
// 1. 窗口是否可见
// 2. 窗口是否可触摸 (FLAG_NOT_TOUCHABLE)
// 3. 窗口是否被遮挡
// 4. 窗口所属应用是否在前台
```

## 3. Overlay 攻击与防护

### 3.1 典型攻击场景

**点击劫持 (Tapjacking)**：
```java
// 恶意应用创建透明 Overlay
WindowManager.LayoutParams params = new WindowManager.LayoutParams(
    WindowManager.LayoutParams.MATCH_PARENT,
    WindowManager.LayoutParams.MATCH_PARENT,
    WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,  // 需要权限
    // 关键 flag
    WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE |      // 不获取焦点
    WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL |    // 不拦截所有触摸
    WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
    PixelFormat.TRANSLUCENT  // 半透明
);

// 设置透明度
params.alpha = 0.0f;  // 完全透明但仍能拦截点击

// 或使用部分透明欺骗用户
params.alpha = 0.1f;  // 几乎看不见

windowManager.addView(overlayView, params);

// 攻击效果：
// 1. 用户以为在点击下层应用
// 2. 实际点击被 Overlay 拦截
// 3. 或者 Overlay 伪装成授权按钮
```

**钓鱼 Overlay**：
```java
// 检测目标应用启动，立即覆盖
// 使用 AccessibilityService 监听窗口变化

@Override
public void onAccessibilityEvent(AccessibilityEvent event) {
    if (event.getEventType() == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
        String packageName = event.getPackageName().toString();
        if (packageName.equals("com.bank.app")) {
            // 立即显示伪造的登录界面
            showPhishingOverlay();
        }
    }
}

// 伪造的登录界面与真实应用 UI 一致
// 用户输入的凭据被恶意应用获取
```

### 3.2 系统防护机制

**SYSTEM_ALERT_WINDOW 权限限制**：
```java
// Android 6.0+: 需要用户手动授予
// Android 10+: 更严格的限制

// 检查权限
if (!Settings.canDrawOverlays(context)) {
    Intent intent = new Intent(
        Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
        Uri.parse("package:" + getPackageName())
    );
    startActivityForResult(intent, REQUEST_CODE);
}

// Android 12+ 进一步限制:
// - 某些系统窗口无法被 Overlay 覆盖
// - 遮挡敏感 UI 时自动隐藏 Overlay
```

**遮挡检测 (Occlusion Detection)**：
```java
// Android 12+ 的 untrusted touch 机制
// frameworks/native/services/inputflinger/dispatcher/InputDispatcher.cpp

// 当检测到不可信 Overlay 遮挡时，触摸事件可能被丢弃
// 条件：
// 1. Overlay 来自不同 UID
// 2. Overlay 设置了可能拦截触摸的 flag
// 3. 触摸点在 Overlay 范围内

// 开发者可以设置 flag 声明窗口"可信"
params.privateFlags |= 
    WindowManager.LayoutParams.PRIVATE_FLAG_TRUSTED_OVERLAY;
// 但此 flag 仅系统应用可用
```

**filterTouchesWhenObscured**：
```xml
<!-- 在 View 上设置，被遮挡时不响应触摸 -->
<Button
    android:filterTouchesWhenObscured="true"
    ... />
```

```java
// 代码设置
view.setFilterTouchesWhenObscured(true);

// 或在 onTouchEvent 中检查
@Override
public boolean onTouchEvent(MotionEvent event) {
    if ((event.getFlags() & MotionEvent.FLAG_WINDOW_IS_OBSCURED) != 0) {
        // 窗口被遮挡，拒绝处理
        return false;
    }
    return super.onTouchEvent(event);
}
```

### 3.3 绕过技术研究

**时序攻击**：
```java
// 在用户点击的瞬间移除 Overlay
// 利用 InputDispatcher 的事件队列延迟

overlayView.setOnTouchListener((v, event) -> {
    if (event.getAction() == MotionEvent.ACTION_DOWN) {
        // 记录点击位置
        lastClickX = event.getRawX();
        lastClickY = event.getRawY();
        
        // 延迟极短时间后移除 Overlay
        handler.postDelayed(() -> {
            windowManager.removeView(overlayView);
            // 此时触摸事件可能传递到下层窗口
        }, 10);
    }
    return true;
});
```

**部分遮挡**：
```java
// 不完全覆盖目标窗口，只覆盖非敏感区域
// 同时显示诱导性提示

// 只在屏幕边缘显示 "看似系统提示" 的 Overlay
params.gravity = Gravity.BOTTOM;
params.height = 200;  // 只占底部一小部分
```

## 4. FLAG_SECURE 保护

### 4.1 工作原理

```java
// 设置窗口为安全窗口
getWindow().setFlags(
    WindowManager.LayoutParams.FLAG_SECURE,
    WindowManager.LayoutParams.FLAG_SECURE
);

// 效果：
// 1. 系统截图显示黑屏
// 2. 录屏时该窗口区域为黑色
// 3. 最近任务缩略图模糊或隐藏
```

**底层实现**：
```cpp
// SurfaceFlinger 中的处理
// frameworks/native/services/surfaceflinger/

// 当 layer 标记为 secure 时
if (layer->isSecure()) {
    // 截图操作：跳过此 layer 或填充黑色
    // 录屏操作：同上
    // 投屏操作：根据策略决定
}
```

### 4.2 绕过研究

**已知绕过方式**：

| 方式 | 原理 | 限制 |
|------|------|------|
| ADB screencap | 某些旧版本未正确处理 | 需要 ADB |
| Root + framebuffer | 直接读取显存 | 需要 Root |
| 虚拟显示器 | 创建虚拟显示不继承 SECURE | 特定场景 |
| Accessibility | 某些版本可读取屏幕内容 | 需要权限 |
| 硬件采集 | HDMI 输出等 | 物理访问 |

**虚拟显示器绕过 (历史漏洞)**：
```java
// CVE-2020-0069 类似问题
// 创建虚拟显示器时，FLAG_SECURE 未正确传递

DisplayManager dm = getSystemService(DisplayManager.class);
VirtualDisplay vd = dm.createVirtualDisplay(
    "capture",
    width, height, dpi,
    surface,  // 接收截图的 surface
    DisplayManager.VIRTUAL_DISPLAY_FLAG_PUBLIC
);

// 在某些版本上，虚拟显示器可以捕获 SECURE 窗口内容
```

## 5. 实战：窗口状态分析

### 5.1 dumpsys 命令

```bash
# 查看所有窗口
adb shell dumpsys window windows

# 输出示例分析
Window #0 Window{abc1234 u0 com.example.app/MainActivity}:
  mDisplayId=0 rootTaskId=5 mSession=Session{...}
  mOwnerUid=10123 mShowToOwnerOnly=true
  mAttrs={(0,0)(fill x fill) sim={...} ty=BASE_APPLICATION
          fmt=TRANSLUCENT
          fl=FLAG_LAYOUT_IN_SCREEN|FLAG_LAYOUT_INSET_DECOR
          pfl=PRIVATE_FLAG_...}
  mBaseLayer=21000 mSubLayer=0
  mToken=ActivityRecord{...}
  mViewVisibility=0x0 mHaveFrame=true mObscured=false

# 关键字段：
# - mOwnerUid: 窗口所属应用
# - ty=: 窗口类型
# - fl=: 窗口 flag
# - mObscured: 是否被遮挡
# - mBaseLayer: 层级

# 查看焦点信息
adb shell dumpsys window | grep -E "mCurrentFocus|mFocusedApp"

# 查看输入焦点
adb shell dumpsys input
```

### 5.2 Frida Hook 示例

```javascript
// Hook WindowManagerService 监控窗口操作
Java.perform(function() {
    var WMS = Java.use("com.android.server.wm.WindowManagerService");
    
    // Hook addWindow
    WMS.addWindow.implementation = function(session, client, attrs, 
                                            viewVisibility, displayId,
                                            requestedVisibleTypes,
                                            outInputChannel, outInsetsState,
                                            outActiveControls, outAttachedFrame) {
        console.log("[WMS] addWindow called");
        console.log("  Type: " + attrs.type.value);
        console.log("  Flags: 0x" + attrs.flags.value.toString(16));
        console.log("  Package: " + attrs.packageName.value);
        
        // 检测可疑 Overlay
        if (attrs.type.value == 2038) {  // TYPE_APPLICATION_OVERLAY
            console.log("  [!] Overlay window detected!");
            console.log("  Alpha: " + attrs.alpha.value);
        }
        
        return this.addWindow(session, client, attrs, viewVisibility,
                             displayId, requestedVisibleTypes,
                             outInputChannel, outInsetsState,
                             outActiveControls, outAttachedFrame);
    };
});
```

### 5.3 检测 Overlay 攻击

```java
// 应用端检测是否被 Overlay 覆盖
public class OverlayDetector {
    
    public static boolean isOverlayDetected(View view) {
        // 方法1：检查触摸事件 flag
        // 在 onTouchEvent 中检查 FLAG_WINDOW_IS_OBSCURED
        
        // 方法2：使用 WindowInsets (Android 11+)
        WindowInsets insets = view.getRootWindowInsets();
        if (insets != null) {
            // 检查是否有遮挡的系统窗口
        }
        
        // 方法3：使用 AccessibilityService (需要权限)
        // 枚举所有窗口，检查是否有可疑 Overlay
        
        return false;
    }
    
    // 在敏感操作前调用
    public void performSensitiveAction(View view) {
        if (isOverlayDetected(view)) {
            showWarning("检测到可能的覆盖攻击");
            return;
        }
        // 执行敏感操作
    }
}
```

## 6. 相关 CVE

| CVE | 类型 | 描述 |
|-----|------|------|
| CVE-2020-0096 | 任务劫持 | StrandHogg 2.0，通过 startActivities 劫持任务栈 |
| CVE-2017-0752 | Overlay | Toast 窗口绕过权限覆盖 |
| CVE-2020-0069 | FLAG_SECURE 绕过 | MediaProjection 可捕获安全窗口 |
| CVE-2021-0487 | 权限绕过 | 后台启动 Activity 绕过 |

## 7. 参考资源

### 官方文档
- [Android Window Management](https://source.android.com/docs/core/architecture)
- [Input System](https://source.android.com/docs/core/interaction/input)
- [Display Support](https://source.android.com/docs/core/display)

### 安全研究
- [StrandHogg Vulnerability](https://developer.android.com/privacy-and-security/risks/strandhogg)
- [Tapjacking Prevention](https://developer.android.com/topic/security/best-practices#tapjacking)

### 源码路径
- WMS: `frameworks/base/services/core/java/com/android/server/wm/`
- SurfaceFlinger: `frameworks/native/services/surfaceflinger/`
- InputFlinger: `frameworks/native/services/inputflinger/`
