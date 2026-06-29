# go-proxy

基于 QUIC 协议的代理，使用 Cisco AnyConnect DTLS 流量伪装。

## 功能

- QUIC 传输（基于 [quic-go](https://github.com/quic-go/quic-go)）
- DTLS 伪装头（Cisco AnyConnect DTLS 13 字节前缀）
- SOCKS5 客户端
- Token 认证
- 断线自动重连
- SSRF 保护

## 使用方法

### 服务端

```bash
PROXY_TOKEN="你的16字节密钥" ./server
```

默认监听 `:8443`。

### 客户端

```bash
PROXY_TOKEN="你的16字节密钥" ./client 服务器地址:8443
```

启动 SOCKS5 代理在 `:1080`。

## 编译

```bash
go build -o server server.go
go build -o client client.go
```

## 环境变量

| 变量 | 必需 | 说明 |
|---|---|---|
| `PROXY_TOKEN` | 是 | 16 字节认证 Token（两端必须一致） |

## 调试

Debug 版输出 DNS 解析、TCP 连接、传输字节数等详细日志：

```bash
go build -o server-debug debug/server-debug.go
PROXY_TOKEN="你的16字节密钥" ./server-debug
```
