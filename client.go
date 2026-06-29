package main

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
)

const (
	ProtocolVersion uint8 = 0x01
	CmdConnect      uint8 = 0x01
	HeaderLength    int   = 20
)

type ClientConfig struct {
	LocalSocksAddr string
	RemoteAddr     string
	SecretToken    []byte
	ServerName     string
}

type ProxyClient struct {
	cfg      ClientConfig
	tlsCfg   *tls.Config
}

func NewProxyClient(cfg ClientConfig) *ProxyClient {
	return &ProxyClient{
		cfg: cfg,
		tlsCfg: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         cfg.ServerName,
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

	serverConn, err := tls.Dial("tcp", c.cfg.RemoteAddr, c.tlsCfg)
	if err != nil {
		log.Printf("⚠️ 连接服务端失败: %v", err)
		return
	}

	header := make([]byte, HeaderLength)
	header[0] = ProtocolVersion
	header[1] = CmdConnect
	copy(header[2:18], c.cfg.SecretToken)
	binary.BigEndian.PutUint16(header[18:20], uint16(len(targetAddr)))

	packet := append(header, []byte(targetAddr)...)
	if _, err := serverConn.Write(packet); err != nil {
		serverConn.Close()
		return
	}

	_, _ = localConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(serverConn, localConn)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(localConn, serverConn)
		if tc, ok := localConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
	serverConn.Close()
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
