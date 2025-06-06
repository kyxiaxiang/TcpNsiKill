# TcpNsiKill

> 🔍 A research-oriented tool for low-level TCP connection termination on Windows using undocumented NSI interfaces.  
> 🧪 For security testing, red team simulations, and educational purposes only.

> 🔍 一个基于未公开 NSI 接口、用于 Windows 上低层 TCP 连接关闭的研究工具。  
> 🧪 仅用于安全测试、红队模拟和教育研究目的。

---
Blog: https://kyxiaxiang.github.io/2025/06/06/%E6%B5%85%E6%B5%85%E5%88%86%E6%9E%90%E9%93%B6%E7%8B%90%E6%9C%80%E6%96%B0%E6%96%AD%E7%BD%91%E6%89%8B%E6%B3%95/
---

## ✨ What is this? / 这是啥？

**TcpNsiKill** provides a stealthy user-mode method to terminate TCP connections of specified processes, bypassing `SetTcpEntry()` and API-level hooks.

**TcpNsiKill** 提供了一种用户态隐藏方式关闭指定进程的 TCP 连接，绕过 `SetTcpEntry()` 和常见的 API 钩子监控。

It directly communicates with the `\\.\Nsi` device driver using native NT functions like `NtDeviceIoControlFile`.

它通过调用如 `NtDeviceIoControlFile` 等原生 NT 函数，直接与 `\\.\Nsi` 驱动设备通信。

---

## 🎯 Use Case / 使用场景

- ✅ Simulate per-process disconnection in red team environments  
- ✅ Research how security software relies on network connectivity  
- ✅ Develop undetectable TCP control mechanisms for study

- ✅ 在红队测试环境中模拟进程级断网  
- ✅ 研究安全软件对网络连通性的依赖性  
- ✅ 开发更难检测的 TCP 控制技术用于学习

---

## ⚙️ How It Works / 工作原理

1. Enumerate all active TCP connections via `GetTcpTable2`  
2. Match target process by name or PID  
3. Build a 72-byte payload (`NSI_SET_PARAMETERS_EX`)  
4. Send IOCTL (0x120013) to `\\.\Nsi` via `NtDeviceIoControlFile`

1. 使用 `GetTcpTable2` 枚举所有活动 TCP 连接  
2. 根据进程名或 PID 匹配目标进程  
3. 构造 72 字节的数据包 (`NSI_SET_PARAMETERS_EX`)  
4. 通过 `NtDeviceIoControlFile` 向 `\\.\Nsi` 发送 IOCTL (0x120013)


---

## 🧱 Project Structure / 项目结构

| File 文件名              | Purpose 用途 |
|--------------------------|-----------------------------|
| `TcpNsiKill.cpp`         | Main logic 主体代码 |
| `README.md`              | Project description 项目说明 |

---

## 🚀 Quick Start / 快速使用

1. Compile with Visual Studio (x64, release mode recommended)  
2. Run as administrator  
3. Modify target process list in `targetProcs`  
4. Observe connections being forcefully dropped

1. 使用 Visual Studio 编译（推荐 x64 Release 模式）  
2. 以管理员权限运行  
3. 修改代码中的 `targetProcs` 目标进程列表  
4. 观察对应连接被强制断开

> ⚠️ Only works on Windows with NSI driver available  
> ⚠️ 请确保目标系统支持 NSI 驱动（Windows 自带）

---

## 🧠 Reference / 参考资料

- Microsoft Docs - [GetTcpTable2](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-gettcptable2)  
- Reverse analysis of `SetTcpEntry` implementation  
- Inspired by: [x86matthew’s post](https://www.x86matthew.com/view_post?id=settcpentry6)

---

## 🧭 Legal Use / 合法使用说明

**This project is strictly for educational, ethical research, and simulation in authorized environments.**

**本项目仅用于教学、安全研究和授权环境中的模拟测试。**

> ❌ NEVER use on unauthorized systems  
> ❌ 禁止在未授权的系统中使用  
> ✅ ALWAYS follow your local laws and security policies  
> ✅ 请始终遵守当地法律法规和公司政策

---
微信公众号 41group
原文 : https://www.notion.so/209c6252b11b802fa69bdde1c05ac01b?source=copy_link
