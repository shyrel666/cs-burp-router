<p>
  <img src="packaging/logo.svg" width="64" height="64" alt="CS-Burp-Router Logo">
</p>

# CS-Burp-Router

面向 Windows 的 C/S 客户端流量分流工具。将 HTTP 和 HTTPS 流量转发到 Burp Suite，数据库及其他 TCP 流量默认直连，并在 Web 控制台实时显示连接状态和分流结果。

## 快速开始

1. 在 Burp Suite 中启动 `127.0.0.1:8080` 代理监听器，并在 **Request handling** 中开启 **Support invisible proxying**。
2. 解压便携包并运行 `cs-burp-router.exe`。默认浏览器会自动打开本地控制台（默认地址 `http://127.0.0.1:18080`）。在程序的终端窗口按 Enter 可重新打开控制台，输入 `link` 后按 Enter 可查看本次启动的完整访问链接。使用 `-no-browser` 可在启动时直接获取完整链接。
3. 支持 SOCKS5 的客户端可直接使用 `127.0.0.1:10808`。需要接管进程时，以管理员身份运行程序，在控制台点击 **选择运行进程**，选中目标客户端后点击 **启动接管**。
4. 调试 HTTPS 时，可在控制台点击 **安装证书**，核对页面展示的 SHA-256 指纹与 Burp 中导出的 CA 证书一致后再确认安装。控制台显示 Windows 当前生效的信任状态，并在清理后仍有匹配证书时提示。

## 从源码构建

在 Windows x64 上准备 Go 1.27.0 或更高版本和 GCC，并启用 CGO。在仓库根目录运行以下 PowerShell 命令。

```powershell
.\scripts\build.ps1
```

脚本会运行静态检查和竞态测试，生成便携包 `dist/cs-burp-router-windows-amd64.zip`。

更多选项见[使用说明](packaging/使用说明.txt)。

便携包包含 [ProxyBridge 4.3.0 Windows](https://github.com/InterceptSuite/ProxyBridge/releases/tag/v4.3.0_Windows) 和 [WinDivert 2.2.2-A x64](https://github.com/basil00/WinDivert/releases/tag/v2.2.2)。[对应的 WinDivert 2.2.2 源码](https://www.reqrypt.org/download/WinDivert-2.2.2-Source.zip)
