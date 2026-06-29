package main

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
)

type ClientConfig struct {
	LocalSocksAddr string
	RemoteAddr     string
	SecretToken    []byte
	ServerName     string
}

type ProxyClient struct {
	cfg    ClientConfig
	client *http.Client
}

func NewProxyClient(cfg ClientConfig) *ProxyClient {
	return &ProxyClient{
		cfg: cfg,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         cfg.ServerName,
				},
			},
			Timeout: 0,
		},
	}
}

func (c *ProxyClient) Start() {
	socksListener, err := net.Listen("tcp", c.cfg.LocalSocksAddr)
	if err != nil {
		log.Fatalf("Failed to bind local Socks5 port: %v", err)
	}
	defer socksListener.Close()

	log.Printf("🚀 客户端已就绪，Socks5 监听在 %s\n", c.cfg.LocalSocksAddr)

	for {
		localConn, err := socksListener.Accept()
		if err != nil {
			continue
		}
		go c.handleLocalSocks(localConn)
	}
}

func (c *ProxyClient) handleLocalSocks(localConn net.Conn) {
	defer localConn.Close()

	buf := make([]byte, 260)
	if _, err := io.ReadFull(localConn, buf[:2]); err != nil {
		return
	}
	nMethods := buf[1]
	if _, err := io.ReadFull(localConn, buf[:nMethods]); err != nil {
		return
	}
	_, _ = localConn.Write([]byte{0x05, 0x00})

	if _, err := io.ReadFull(localConn, buf[:4]); err != nil {
		return
	}
	if buf[1] != 0x01 {
		return
	}

	var targetHost string
	switch buf[3] {
	case 0x01:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(localConn, ipBuf); err != nil {
			return
		}
		targetHost = net.IP(ipBuf).String()
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(localConn, lenBuf); err != nil {
			return
		}
		nameBuf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(localConn, nameBuf); err != nil {
			return
		}
		targetHost = string(nameBuf)
	case 0x04:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(localConn, ipBuf); err != nil {
			return
		}
		targetHost = net.IP(ipBuf).String()
	default:
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(localConn, portBuf); err != nil {
		return
	}
	targetPort := binary.BigEndian.Uint16(portBuf)
	targetAddr := net.JoinHostPort(targetHost, strconv.FormatUint(uint64(targetPort), 10))

	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, "https://"+c.cfg.RemoteAddr+"/tunnel", pr)
	if err != nil {
		log.Printf("⚠️ 创建请求失败: %v", err)
		return
	}
	req.Header.Set("X-Token", string(c.cfg.SecretToken))
	req.Header.Set("X-Target", targetAddr)
	req.Close = false

	resp, err := c.client.Do(req)
	if err != nil {
		log.Printf("⚠️ 连接服务端失败: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("⚠️ 服务端拒绝: %d", resp.StatusCode)
		return
	}

	_, _ = localConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(pw, localConn)
		pw.Close()
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(localConn, resp.Body)
		if tc, ok := localConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
}

func getSecretToken() []byte {
	if token := os.Getenv("PROXY_TOKEN"); len(token) == 16 {
		return []byte(token)
	}
	log.Println("⚠️ 环境变量 PROXY_TOKEN 未设置或长度不是 16，使用默认硬编码 Token（仅供测试）")
	return []byte("my_secure_token!")
}

func main() {
	addr := os.Getenv("PROXY_SERVER")
	if addr == "" {
		addr = "server_ip:443"
	}

	client := NewProxyClient(ClientConfig{
		LocalSocksAddr: "127.0.0.1:1080",
		RemoteAddr:     addr,
		SecretToken:    getSecretToken(),
		ServerName:     "www.cisco.com",
	})

	client.Start()
}
