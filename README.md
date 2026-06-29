# go-proxy

基于 HTTP/2 (TLS) 的代理服务。

## 功能

- HTTP/2 传输（标准 HTTPS，难以与正常流量区分）
- SOCKS5 客户端
- Token 认证
- SSRF 保护

## 使用方法

### 服务端

```bash
PROXY_TOKEN="你的16字节密钥" ./server
```

默认监听 `:443`，可通过 `PROXY_PORT` 环境变量指定端口。

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
| `PROXY_PORT` | 服务端 | 监听端口（默认 `443`） |
