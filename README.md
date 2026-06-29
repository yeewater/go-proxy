# go-proxy

基于 TCP+TLS 的代理服务。

## 功能

- TLS 传输（标准 HTTPS 端口 443，难以与正常流量区分）
- SOCKS5 客户端
- Token 认证
- SSRF 保护

## 使用方法

### 服务端

```bash
PROXY_TOKEN="你的16字节密钥" ./server
```

默认监听 `:443`。

### 客户端

```bash
PROXY_TOKEN="你的16字节密钥" PROXY_SERVER="服务器地址:443" ./client
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
| `PROXY_SERVER` | 客户端 | 服务端地址（默认 `server_ip:443`） |

## 证书

服务端优先加载当前目录的 `server.crt` / `server.key`，不存在则自动生成自签名证书。

建议用 Let's Encrypt 的真实域名证书替换，流量看起就是普通 HTTPS。
