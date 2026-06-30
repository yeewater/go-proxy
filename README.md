# go-proxy

[English](#english) | [中文](#中文)

---

## English

TCP+TLS proxy with fallback, time-based keys, padding, and uTLS fingerprint.

### Usage

#### Server (VPS)

```bash
PROXY_TOKEN="your-16-byte-token" PROXY_PORT=":8443" FALLBACK="127.0.0.1:8085" FALLBACK_HOST="example.com" ./server
```

| Env | Description |
|-----|-------------|
| `PROXY_TOKEN` | 16-byte secret key |
| `PROXY_TOKEN_FILE` | Read key from file (alternative to PROXY_TOKEN) |
| `PROXY_PORT` | Listen port (default `:443`) |
| `FALLBACK` | HTTP backend for unauthenticated connections |
| `FALLBACK_HOST` | Host header for synthetic fallback request (default `localhost`) |

#### Client (Local)

```bash
PROXY_SERVER="your-server:8443" PROXY_TOKEN="your-16-byte-token" PROXY_SNI="your-domain.com" ./client
```

| Env | Description |
|-----|-------------|
| `PROXY_SERVER` | Server address |
| `PROXY_TOKEN` | 16-byte secret key (must match server) |
| `PROXY_TOKEN_FILE` | Read key from file |
| `PROXY_SNI` | TLS SNI (set to server's domain) |

Client listens on `127.0.0.1:1080` (SOCKS5). Configure browser/system to use SOCKS5 proxy at this address.

### Build

```bash
CGO_ENABLED=0 go build -o server server.go
CGO_ENABLED=0 go build -o client client.go
```

---

## 中文

TCP+TLS 代理，支持回落、时间密钥、填充和 uTLS 指纹。

### 使用方法

#### 服务端（VPS）

```bash
PROXY_TOKEN="你的-16-字节密钥" PROXY_PORT=":8443" FALLBACK="127.0.0.1:8085" FALLBACK_HOST="example.com" ./server
```

| 环境变量 | 说明 |
|-----------|------|
| `PROXY_TOKEN` | 16 字节密钥 |
| `PROXY_TOKEN_FILE` | 从文件读取密钥（替代 PROXY_TOKEN） |
| `PROXY_PORT` | 监听端口（默认 `:443`） |
| `FALLBACK` | 未认证连接的 HTTP 后端 |
| `FALLBACK_HOST` | synthetic fallback 请求的 Host 头（默认 `localhost`） |

#### 客户端（本地）

```bash
PROXY_SERVER="你的服务器:8443" PROXY_TOKEN="你的-16-字节密钥" PROXY_SNI="你的域名.com" ./client
```

| 环境变量 | 说明 |
|-----------|------|
| `PROXY_SERVER` | 服务器地址 |
| `PROXY_TOKEN` | 16 字节密钥（必须与服务器一致） |
| `PROXY_TOKEN_FILE` | 从文件读取密钥 |
| `PROXY_SNI` | TLS SNI（设为服务器的域名） |

客户端监听 `127.0.0.1:1080`（SOCKS5）。在浏览器/系统中配置 SOCKS5 代理为此地址。

### 编译

```bash
CGO_ENABLED=0 go build -o server server.go
CGO_ENABLED=0 go build -o client client.go
```
