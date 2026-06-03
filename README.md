# MoonBit SSH 客户端

使用 MoonBit 实现的 SSH 客户端库，支持 SSH 连接、认证、交互式会话等功能。

## 项目简介

本项目是一个纯 MoonBit 实现的 SSH 客户端库，旨在为 MoonBit 生态提供 SSH 协议支持能力。项目可用于：
- 远程服务器管理
- 自动化运维脚本
- SSH 协议教学与研究

## 项目方向

- 应用生态：流行网络协议的 MoonBit 实现

## 功能特性

- SSH 协议连接
- 用户名/密码认证
- 密钥认证支持
- 交互式会话
- 命令执行

## 安装方式

```moonbit
moon add github.com/your-repo/moonbit-ssh
```

## 使用示例

```moonbit
let ssh = SSH::connect("hostname", 22)?
ssh.auth_password("username", "password")?
let output = ssh.exec("ls -la")?
print(output)
```

## 项目结构

```
src/
  ssh.mbt          # SSH 连接与认证
  channel.mbt     # 通道管理
  kex.mbt         # 密钥交换
test/
  connect_test.mbt
  auth_test.mbt
```

## 许可证

MIT License