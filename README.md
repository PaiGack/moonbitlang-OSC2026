# MoonBit SSH 客户端

使用 MoonBit 实现的 SSH 客户端库，为 MoonBit 生态提供 SSH 协议支持能力。

## 项目简介

本项目是一个纯 MoonBit 实现的 SSH 客户端库，目前正在开发中，已完成传输层的基础实现。项目目标是：

- 远程服务器管理
- 自动化运维脚本
- SSH 协议教学与研究

## 项目方向

- 应用生态：流行网络协议的 MoonBit 实现

## 当前实现

- SSH 传输层基础架构
- TCP 连接支持

## 安装方式

```moonbit
moon add github.com/PaiGack/moonbitlang-OSC2026
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
code/
├── cmd/main/main.mbt       # 主程序入口
├── ssh_client.mbt         # SSH 客户端核心库
├── ssh_client_test.mbt    # 黑盒测试
└── ssh_client_wbtest.mbt  # 白盒测试
```

## 开发指南

```bash
# 构建项目
moon build

# 运行测试
moon test

# 运行主程序
moon run cmd/main

# 格式化代码
moon fmt
```

## 许可证

MIT License