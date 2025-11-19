<div align="center">

# 🚀 NBpxeserver

**图形化PXE网络启动服务器**  
*原生支持类dnsmasq动态菜单，完美兼容BIOS与UEFI*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.6+](https://img.shields.io/badge/Python-3.6+-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/Version-1.0.3-green.svg)](version.txt)

**[简体中文](#简介) | [English](#about-the-project)**

![NBpxeserver Screenshot](screenshot.png)

</div>

---

## 📖 简介

NBpxeserver 是一款用 Python 编写的**功能强大的PXE网络启动服务器**，拥有直观的图形用户界面（GUI），旨在将复杂的网络启动配置过程变得**简单化、可视化**。

无论您是需要批量部署操作系统的系统管理员，还是希望通过网络运行各种维护工具的技术爱好者，NBpxeserver 都能帮助您轻松、快速地搭建起一套稳定可靠的PXE启动环境。

### 🌟 为什么选择 NBpxeserver？

- ✅ **零门槛使用** - 图形界面操作，无需编辑配置文件
- ✅ **功能完整** - DHCP/ProxyDHCP/TFTP/HTTP/SMB 一站式服务
- ✅ **高度兼容** - 支持传统BIOS和现代UEFI，自动识别客户端类型
- ✅ **动态菜单** - 根据客户端MAC/UUID自动生成定制化启动菜单
- ✅ **跨平台** - 纯Python实现，便携易部署
- ✅ **开源免费** - MIT协议，自由使用和修改

---

## ✨ 主要功能

### 🖥️ 图形用户界面
所有核心功能都集成在简洁的图形界面中，无需编辑复杂的配置文件，点击鼠标即可完成设置。

### 🔄 全面的启动支持
完美兼容传统的 **BIOS (Legacy)** 和现代的 **UEFI** 固件（包括IA32和x64），能自动识别客户端架构类型并发送对应的启动文件。

### 🎯 类 Dnsmasq 动态菜单
核心亮点功能！服务器能够像 Dnsmasq 一样，根据客户端的 **MAC 地址**、**UUID** 或其他标识动态生成专属的PXE启动菜单，实现高度定制化的启动服务。

### 🚀 多启动加载器支持
内置支持 **iPXE**、**GRUB4DOS**、**Syslinux** 等多种流行的启动加载器，您可以根据需求灵活选择。

### 📡 完整的网络服务
- **DHCP服务器** - 完整模式，支持IP地址池管理
- **ProxyDHCP** - 代理模式，与现有DHCP服务器共存
- **TFTP服务器** - 高性能文件传输，支持多线程
- **HTTP服务器** - HTTP/1.1协议，支持Range请求和断点续传
- **SMB共享** - Windows文件共享（仅Windows）

### 🎨 高级特性
- ✅ **HTTP/1.1支持** - 兼容httpdisk等磁盘挂载工具
- ✅ **客户端管理** - 实时监控客户端连接状态
- ✅ **传输进度** - 实时显示文件传输进度和速度
- ✅ **智能探测** - 自动探测局域网中的其他DHCP服务器
- ✅ **日志系统** - 详细的操作日志，便于故障排查

### 💼 专为 Windows 优化
完美适配 Windows 操作系统，提供简单易用的启动/停止服务控制，支持一键创建SMB共享。

---

## 🚀 快速上手

按照以下步骤，您可以在**几分钟内**启动并运行您的PXE服务器。

### 1️⃣ 准备环境
确保您的电脑上安装了 **Python 3.6+**
```bash
python --version
```

### 2️⃣ 下载项目
下载本项目所有文件，并解压到一个文件夹中：
```
例如: C:\NBpxeserver 或 D:\PXE
```

### 3️⃣ 配置目录
将您的启动文件（如 WIM、ISO、镜像文件等）放入对应文件夹：
- **TFTP文件**: 放入 `tftp_root` 文件夹
- **HTTP文件**: 放入 `http_root` 文件夹
- **SMB共享**: 放入 `smb_root` 文件夹（可选）

程序首次运行时会自动创建这些目录。

### 4️⃣ 运行服务器
1. 直接运行 **`NBPxeServer.py`** 文件
2. 程序会自动检测并填入本机IP地址，您也可以手动修改
3. 根据您的网络环境，选择工作模式：
   - **DHCP模式** - 完整DHCP服务器（确保网络中没有其他DHCP）
   - **ProxyDHCP模式** - 与现有DHCP服务器共存（推荐）
4. 点击 **"启动服务"** 按钮
5. 观察日志窗口，确保所有服务已成功启动

### 5️⃣ 客户端启动
将需要启动的客户端电脑（裸机或虚拟机）设置为从 **网络启动 (PXE Boot)**，启动后您将看到由服务器发送的启动菜单。

---

## 📋 系统要求

### 服务器端
- **操作系统**: Windows 7/8/10/11 或更高版本
- **Python**: 3.6 或更高版本
- **网络**: 至少一个网络接口
- **权限**: 
  - DHCP/TFTP需要管理员权限（端口67/69）
  - SMB共享需要管理员权限

### 客户端
- 支持PXE网络启动的主板或虚拟机
- BIOS或UEFI固件
- 连接到同一局域网

---

## 📚 配置文件说明

首次运行后，程序会自动创建 `NBpxe.ini` 配置文件。您可以通过GUI界面修改大部分设置，也可以直接编辑INI文件进行高级配置。

### 主要配置节
- `[SERVER]` - 服务器基本设置
- `[DHCP]` - DHCP服务配置
- `[MENU]` - PXE菜单设置
- `[MENU_xxx]` - 具体的菜单项
- `[MAC_xx:xx:xx:xx:xx:xx]` - MAC地址特定配置

详细配置说明请参考自动生成的配置文件中的注释。

---

## 🔧 常见应用场景

### 💻 企业批量部署
- 无人值守安装 Windows/Linux 操作系统
- 批量部署企业定制镜像
- 多版本系统并行部署

### 🛠️ 系统维护与恢复
- 网络启动 WinPE 维护环境
- 磁盘克隆与备份
- 系统故障诊断和恢复

### 🎓 技术实验与教学
- 网络启动原理教学
- 多操作系统测试环境
- 虚拟化实验平台

### 📀 ISO文件挂载
- 支持通过HTTP挂载ISO文件
- 兼容httpdisk等虚拟磁盘工具
- HTTP/1.1协议，Range请求支持

---

## 📝 版本历史

### v1.0.3 (2025-11-19) - 最新版本
- ✨ **重要更新**: 升级HTTP协议从1.0到1.1
- ✅ 新增HEAD方法支持
- ✅ 添加Last-Modified和ETag响应头部
- 🐛 修复httpdisk无法挂载ISO文件的问题
- 🔧 删除重复代码，优化代码质量
- 📈 增强与标准HTTP客户端的兼容性

### v1.0.2
- 改进客户端管理功能
- 优化TFTP传输性能
- 修复BIOS兼容性问题

### v1.0.0
- 首次发布
- 基础PXE服务器功能

---

## 🙏 致谢

感谢以下开源项目和技术：

- [Python](https://www.python.org/) - 强大的编程语言
- [Dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html) - 灵感来源
- [iPXE](https://ipxe.org/) - 强大的网络启动固件
- [GRUB4DOS](https://github.com/chenall/grub4dos) - 经典的启动加载器

以及所有为开源社区做出贡献的开发者们！❤️

---

## 📜 开源协议

本项目采用 [MIT License](LICENSE) 协议开源。

您可以自由地：
- ✅ 使用本软件
- ✅ 修改本软件
- ✅ 分发本软件
- ✅ 商业使用

唯一要求是保留原作者的版权声明。

---

## 💬 支持与反馈

如果您在使用过程中遇到问题或有任何建议，欢迎：
- 📧 提交 Issue
- 💡 提出功能建议
- 🔀 提交 Pull Request

---

## 😄 声明

**郑重声明**：本项目的全部代码均由 **Google AI** 编写。

作者本人在此过程中的全部工作，是使用一个仅包含三个按键（`Ctrl`、`C`、`V`）的特制键盘完成的。

这是一个AI辅助开发的典范案例，展示了人工智能在复杂系统开发中的巨大潜力。🤖✨

---

<div align="center">

**Made with ❤️ by 江南一根葱 (懒汉工作室)**

*Powered by Google AI & Ctrl+C+V*

⭐ 如果这个项目对您有帮助，请给个Star支持一下！⭐

</div>

---

## About The Project

NBpxeserver is a powerful **PXE network boot server** written in Python, featuring an intuitive **Graphical User Interface (GUI)**. It is designed to simplify and visualize the complex process of configuring a network boot environment. 

Whether you are a system administrator needing to deploy operating systems in bulk, or a tech enthusiast looking to run various maintenance tools over the network, NBpxeserver helps you build a stable and reliable PXE boot solution with **ease and speed**.

### Key Features

- **🖥️ Graphical Interface** - All core functions integrated into a clean GUI
- **🔄 Comprehensive Boot Support** - Compatible with BIOS and UEFI (IA32/x64)
- **🎯 Dnsmasq-style Dynamic Menus** - Generate custom boot menus based on MAC/UUID
- **🚀 Multi-bootloader Support** - iPXE, GRUB4DOS, Syslinux, and more
- **📡 Full Network Services** - DHCP, ProxyDHCP, TFTP, HTTP, SMB
- **💼 Windows-Friendly** - Perfectly adapted for Windows OS

### Quick Start

1. Install Python 3.6+
2. Download and extract project files
3. Place boot files in `tftp_root` or `http_root`
4. Run `NBPxeServer.py`
5. Click "Start Server" button
6. Boot your client from network

For detailed instructions, see the Chinese documentation above.

### License

Distributed under the MIT License. See `LICENSE` for more information.

### Declaration

**Full disclosure**: This entire project was coded by Google AI. The author's role was limited to using a highly specialized three-key keyboard consisting of only `CTRL`, `C`, and `V`. 🎹😄
