# CVEs

## 索引

- [按版本查看](indexes/by-version.md) - Android 按版本分类
- [按层级查看](indexes/by-layer.md) - Kernel/Framework/Native
- [按组件查看](indexes/by-component.md) - Binder/PMS/GPU 等
- [按漏洞类型查看](indexes/by-cwe.md) - UAF/OOB/权限提升等

## 漏洞列表

### 2025

| CVE | CVSS | CWE | 层级 | 组件 | 概述 | ITW |
|-----|------|-----|------|------|------|-----|
| [CVE-2025-68260](entries/CVE-2025-68260.md) | 7.8 | CWE-416 | Kernel | Binder | Binder driver vulnerability | |
| [CVE-2025-48633](entries/CVE-2025-48633.md) | 7.8 | CWE-416 | Kernel | Binder | Binder driver vulnerability | |
| [CVE-2025-48593](entries/CVE-2025-48593.md) | 7.8 | CWE-416 | Native | System/Core | Native system component vulnerability | |
| [CVE-2025-48554](entries/CVE-2025-48554.md) | 7.8 | CWE-416 | Native | System/Core | Native system component vulnerability | |
| [CVE-2025-48545](entries/CVE-2025-48545.md) | 7.8 | CWE-269 | Framework | System/Framework | Framework component vulnerability | |
| [CVE-2025-48543](entries/CVE-2025-48543.md) | 7.8 | CWE-416 | Native | System/Core | Native system component vulnerability | |
| [CVE-2025-48535](entries/CVE-2025-48535.md) | 7.8 | CWE-269 | Native | System/Core | Native system component vulnerability | |
| [CVE-2025-48530](entries/CVE-2025-48530.md) | 7.8 | CWE-416 | Native | System/Core | Native system component vulnerability | |
| [CVE-2025-48524](entries/CVE-2025-48524.md) | 7.8 | CWE-416 | Native | System/Core | Native system component vulnerability | |
| [CVE-2025-38352](entries/CVE-2025-38352.md) | 7.8 | CWE-416 | Kernel | Kernel/Core | Kernel component vulnerability | |
| [CVE-2025-32323](entries/CVE-2025-32323.md) | 7.8 | CWE-416 | Native | System/Core | Native system component vulnerability | |
| [CVE-2025-27363](entries/CVE-2025-27363.md) | 8.1 | CWE-787 | Native | System/FreeType | FreeType font subglyph OOB write → code execution (ITW, zero-click) | ⭐ |
| [CVE-2025-26464](entries/CVE-2025-26464.md) | 7.8 | CWE-416 | Native | System/Core | Native system component vulnerability | |
| [CVE-2025-26443](entries/CVE-2025-26443.md) | 7.8 | CWE-269 | Framework | System/Framework | Framework component vulnerability | |
| [CVE-2025-22432](entries/CVE-2025-22432.md) | 7.8 | CWE-416 | Native | System/Core | Native system component vulnerability | |
| [CVE-2025-22413](entries/CVE-2025-22413.md) | 7.8 | CWE-787 | Kernel | Kernel/Core | Kernel component vulnerability | |
| [CVE-2025-20655](entries/CVE-2025-20655.md) | 5.5 | CWE-200 | Native | Keystore/TEE | MediaTek Keymaster TEE information disclosure | |
| [CVE-2025-0091](entries/CVE-2025-0091.md) | 7.8 | CWE-416 | Native | System/Core | Native system component vulnerability | |
| [CVE-2025-0078](entries/CVE-2025-0078.md) | 7.8 | CWE-416 | Kernel | Kernel/Core | Kernel component vulnerability | |
| [CVE-2025-0076](entries/CVE-2025-0076.md) | 7.8 | CWE-269 | Framework | System/Framework | Framework privilege escalation | |

### 2024

| CVE | CVSS | CWE | 层级 | 组件 | 概述 | ITW |
|-----|------|-----|------|------|------|-----|
| [CVE-2024-53197](entries/CVE-2024-53197.md) | 7.8 | CWE-787 | Kernel | Kernel/ALSA-USB | Linux kernel ALSA USB-audio OOB memory access (ITW, Cellebrite chain) | ⭐ |
| [CVE-2024-53150](entries/CVE-2024-53150.md) | 7.1 | CWE-125 | Kernel | Kernel/ALSA-USB | Linux kernel ALSA USB-audio OOB read (ITW, Cellebrite chain) | ⭐ |
| [CVE-2024-53104](entries/CVE-2024-53104.md) | 7.8 | CWE-787 | Kernel | Kernel/USB-UVC | Linux kernel USB Video Class OOB write (ITW, Cellebrite chain) | ⭐ |
| [CVE-2024-50302](entries/CVE-2024-50302.md) | 7.8 | CWE-908 | Kernel | Kernel/HID | Linux kernel HID core uninitialized buffer → info leak (ITW, Cellebrite chain) | ⭐ |
| [CVE-2024-49744](entries/CVE-2024-49744.md) | 7.8 | CWE-502 | Framework | AMS/AccountManager | AccountManagerService unsafe deserialization → EoP | |
| [CVE-2024-49733](entries/CVE-2024-49733.md) | 5.5 | CWE-269 | Framework | System/Settings | ServiceListing reload logic error → hide NLS from Settings | |
| [CVE-2024-49721](entries/CVE-2024-49721.md) | 7.8 | CWE-269 | Framework | Framework/Core | Framework privilege escalation | |
| [CVE-2024-45445](entries/CVE-2024-45445.md) | 5.5 | CWE-200 | Native | Keystore/TEE | Keystore/TEE information disclosure | |
| [CVE-2024-43093](entries/CVE-2024-43093.md) | 7.8 | CWE-22 | Framework | Framework/ExternalStorage | ExternalStorageProvider Unicode normalization path traversal (ITW) | ⭐ |
| [CVE-2024-43090](entries/CVE-2024-43090.md) | 5.0 | CWE-862 | Framework | Framework/Core | Missing permission check → cross-user image read | |
| [CVE-2024-43081](entries/CVE-2024-43081.md) | 7.8 | CWE-269 | Framework | PMS | InstallPackageHelper carrier restriction bypass → EoP | |
| [CVE-2024-43080](entries/CVE-2024-43080.md) | 7.8 | CWE-502 | Framework | System/Settings | AppRestrictionsFragment unsafe deserialization → EoP (Intent Redirect) | |
| [CVE-2024-40660](entries/CVE-2024-40660.md) | 7.8 | CWE-269 | Framework | Framework/Core | Framework component privilege escalation | |
| [CVE-2024-40652](entries/CVE-2024-40652.md) | 7.8 | CWE-862 | Framework | System/Settings | SettingsHomepageActivity missing permission check → EoP during provisioning | |
| [CVE-2024-40650](entries/CVE-2024-40650.md) | 7.8 | CWE-862 | Framework | System/Settings | Settings FRP bypass via wifi_item_edit_content | |
| [CVE-2024-36971](entries/CVE-2024-36971.md) | 7.8 | CWE-416 | Kernel | Kernel/Networking | Linux kernel __dst_negative_advice() UAF (ITW, Google TAG) | ⭐ |
| [CVE-2024-32896](entries/CVE-2024-32896.md) | 7.8 | CWE-269 | Framework | Pixel/Firmware | Pixel firmware logic error → privilege escalation (ITW, factory reset interrupt) | ⭐ |
| [CVE-2024-31320](entries/CVE-2024-31320.md) | 7.8 | CWE-862 | Framework | Framework/CDM | CompanionDeviceManager setSkipPrompt bypass | |
| [CVE-2024-29779](entries/CVE-2024-29779.md) | 7.8 | CWE-269 | Native | Keystore/KeyMint | KeyMint TEE privilege escalation | |
| [CVE-2024-29745](entries/CVE-2024-29745.md) | 5.5 | CWE-200 | Bootloader | Pixel/Fastboot | Pixel fastboot firmware memory not zeroed → info disclosure (ITW, Cellebrite) | ⭐ |
| [CVE-2024-20865](entries/CVE-2024-20865.md) | 6.8 | CWE-287 | Bootloader | Samsung/Bootloader | Samsung bootloader authentication bypass → flash arbitrary images | |
| [CVE-2024-20832](entries/CVE-2024-20832.md) | 6.7 | CWE-787 | Bootloader | Samsung/Bootloader | Samsung Little Kernel bootloader heap overflow | |
| [CVE-2024-0044](entries/CVE-2024-0044.md) | 7.8 | CWE-20 | Framework | PMS | PackageInstallerService installer name injection → run-as bypass (ITW) | ⭐ |
| [CVE-2024-0025](entries/CVE-2024-0025.md) | 7.8 | CWE-269 | Framework | AMS | sendIntentSender logic error → background activity launch | |

### 2023

| CVE | CVSS | CWE | 层级 | 组件 | 概述 | ITW |
|-----|------|-----|------|------|------|-----|
| [CVE-2023-4863](entries/CVE-2023-4863.md) | 8.8 | CWE-787 | Native | System/libwebp | libwebp heap buffer overflow in BuildHuffmanTable (ITW) | ⭐ |
| [CVE-2023-4211](entries/CVE-2023-4211.md) | 7.8 | CWE-416 | Kernel | GPU/Mali | ARM Mali GPU driver use-after-free (ITW) | ⭐ |
| [CVE-2023-21255](entries/CVE-2023-21255.md) | 7.8 | CWE-416 | Kernel | Binder | Binder driver use-after-free | |
| [CVE-2023-21036](entries/CVE-2023-21036.md) | 5.5 | CWE-200 | Framework | System/Markup | aCropalypse — Markup screenshot data not truncated | |
| [CVE-2023-20938](entries/CVE-2023-20938.md) | 7.8 | CWE-416 | Kernel | Binder | Binder driver use-after-free in binder_transaction | |

### 2022

| CVE | CVSS | CWE | 层级 | 组件 | 概述 | ITW |
|-----|------|-----|------|------|------|-----|
| [CVE-2022-4543](entries/CVE-2022-4543.md) | 5.5 | CWE-281 | Kernel | Kernel/Core | EntryBleed — KASLR bypass via prefetch side-channel | |
| [CVE-2022-20186](entries/CVE-2022-20186.md) | 7.8 | CWE-787 | Kernel | GPU/Mali | ARM Mali GPU driver out-of-bounds write | |
| [CVE-2022-0847](entries/CVE-2022-0847.md) | 7.8 | CWE-281 | Kernel | Kernel/Core | Dirty Pipe — pipe buffer flag not cleared on splice | |

### 2021

| CVE | CVSS | CWE | 层级 | 组件 | 概述 | ITW |
|-----|------|-----|------|------|------|-----|
| [CVE-2021-1905](entries/CVE-2021-1905.md) | 7.8 | CWE-416 | Kernel | GPU/Adreno | Qualcomm Adreno GPU use-after-free (ITW) | ⭐ |
| [CVE-2021-1048](entries/CVE-2021-1048.md) | 7.8 | CWE-416 | Kernel | Kernel/Core | epoll use-after-free in ep_loop_check_proc (ITW) | ⭐ |
| [CVE-2021-0928](entries/CVE-2021-0928.md) | 7.8 | CWE-416 | Kernel | Binder | Parcel deserialization type confusion via OutputConfiguration | |
| [CVE-2021-0920](entries/CVE-2021-0920.md) | 7.8 | CWE-416 | Kernel | Kernel/AF_UNIX | AF_UNIX garbage collection race condition (ITW, Google TAG) | ⭐ |
| [CVE-2021-0478](entries/CVE-2021-0478.md) | 7.8 | CWE-269 | Framework | PMS | PendingIntent hijack in PackageManagerService | |