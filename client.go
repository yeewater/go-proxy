package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	ProtocolVersion uint8 = 0x01
	CmdConnect      uint8 = 0x01
	HeaderLength    int   = 20
)

type ClientConfig struct {
	LocalSocksAddr string
	RemoteUDPAddr  string
	SecretToken    []byte
	ServerName     string
}

var AnyConnectHeader = []byte{0x17, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01}

type DisguiseUDPConn struct {
	net.PacketConn
}

func (c *DisguiseUDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	tempBuf := make([]byte, 65535)
	n, addr, err := c.PacketConn.ReadFrom(tempBuf)
	if err != nil {
		return 0, nil, err
	}
	if n < len(AnyConnectHeader) || !bytes.Equal(tempBuf[:len(AnyConnectHeader)], AnyConnectHeader) {
		return 0, addr, errors.New("dropped malicious non-AnyConnect tracking packet")
	}
	copied := copy(b, tempBuf[len(AnyConnectHeader):n])
	return copied, addr, nil
}

func (c *DisguiseUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	_, err := c.PacketConn.WriteTo(append(AnyConnectHeader, b...), addr)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

type ProxyClient struct {
	cfg        ClientConfig
	quicConn   quic.Connection
	connMutex  sync.RWMutex // 保护全局物理连接
	secureUDP  *DisguiseUDPConn
	remoteUDP  *net.UDPAddr
	tlsCfg     *tls.Config
	quicCfg    *quic.Config
}

func NewProxyClient(cfg ClientConfig) *ProxyClient {
	if len(cfg.SecretToken) != 16 {
		log.Fatalf("Fatal: SecretToken must be exactly 16 bytes")
	}
	return &ProxyClient{cfg: cfg}
}

// getOrDialConn 核心修复：动态获取连接，连接断开时自动触发断线重连
func (c *ProxyClient) getOrDialConn() (quic.Connection, error) {
	c.connMutex.RLock()
	if c.quicConn != nil && c.quicConn.Context().Err() == nil {
		defer c.connMutex.RUnlock()
		return c.quicConn, nil
	}
	c.connMutex.RUnlock()

	c.connMutex.Lock()
	defer c.connMutex.Unlock()

	// 双重检查，防止并发建立多条长连接
	if c.quicConn != nil && c.quicConn.Context().Err() == nil {
		return c.quicConn, nil
	}

	log.Printf("🔄 Tunnel is down or uninitialized. Dialing new QUIC connection to %s...", c.cfg.RemoteUDPAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := quic.Dial(ctx, c.secureUDP, c.remoteUDP, c.tlsCfg, c.quicCfg)
	if err != nil {
		return nil, err
	}
	c.quicConn = conn
	return conn, nil
}

func (c *ProxyClient) Start() {
	socksListener, err := net.Listen("tcp", c.cfg.LocalSocksAddr)
	if err != nil {
		log.Fatalf("Failed to bind local Socks5 port: %v", err)
	}
	defer socksListener.Close()

	rawUDPConn, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		log.Fatalf("Failed to bind local UDP: %v", err)
	}
	defer rawUDPConn.Close()
	c.secureUDP = &DisguiseUDPConn{PacketConn: rawUDPConn}

	c.tlsCfg = &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
		ServerName:         c.cfg.ServerName,
	}
	c.quicCfg = &quic.Config{
		MaxIdleTimeout:  60 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
	}

	c.remoteUDP, err = net.ResolveUDPAddr("udp", c.cfg.RemoteUDPAddr)
	if err != nil {
		log.Fatalf("Failed to resolve remote address: %v", err)
	}

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

	// A. Socks5 极简协商阶段
	buf := make([]byte, 260)
	if _, err := io.ReadFull(localConn, buf[:2]); err != nil {
		return
	}
	nMethods := buf[1]
	if _, err := io.ReadFull(localConn, buf[:nMethods]); err != nil {
		return
	}
	_, _ = localConn.Write([]byte{0x05, 0x00})

	// B. 核心修复：精准解析 Socks5 目标地址，彻底移除流读取错位 Bug
	// 先读固定前 4 字节 (VER, CMD, RSV, ATYP)
	if _, err := io.ReadFull(localConn, buf[:4]); err != nil {
		return
	}
	if buf[1] != 0x01 { // 仅放行 TCP CONNECT
		return
	}

	var targetHost string
	atyp := buf[3]

	switch atyp {
		case 0x01: // IPv4 (固定 4 字节)
			ipBuf := make([]byte, 4)
			if _, err := io.ReadFull(localConn, ipBuf); err != nil {
				return
			}
			targetHost = net.IP(ipBuf).String()
		case 0x03: // 域名格式 (1字节长度 + 动态内容)
			lenBuf := make([]byte, 1)
			if _, err := io.ReadFull(localConn, lenBuf); err != nil {
				return
			}
			nameLen := lenBuf[0]
			nameBuf := make([]byte, nameLen)
			if _, err := io.ReadFull(localConn, nameBuf); err != nil {
				return
			}
			targetHost = string(nameBuf)
		case 0x04: // IPv6 (固定 16 字节)
			ipBuf := make([]byte, 16)
			if _, err := io.ReadFull(localConn, ipBuf); err != nil {
				return
			}
			targetHost = net.IP(ipBuf).String()
		default:
			return
	}

	// 读取最后的固定 2 字节端口
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(localConn, portBuf); err != nil {
		return
	}
	targetPort := binary.BigEndian.Uint16(portBuf)
	targetAddr := net.JoinHostPort(targetHost, strconv.FormatUint(uint64(targetPort), 10))

	// C. 获取当前存活的全局 QUIC 连接通道
	quicConn, err := c.getOrDialConn()
	if err != nil {
		log.Printf("⚠️ Failed to establish active tunnel to VPS: %v", err)
		return
	}

	stream, err := quicConn.OpenStream()
	if err != nil {
		return
	}
	defer stream.Close()

	// 组装私有控制头并发射
	header := make([]byte, HeaderLength)
	header[0] = ProtocolVersion
	header[1] = CmdConnect
	copy(header[2:18], c.cfg.SecretToken)
	binary.BigEndian.PutUint16(header[18:20], uint16(len(targetAddr)))

	packet := append(header, []byte(targetAddr)...)
	if _, err := stream.Write(packet); err != nil {
		return
	}

	// 响应本地浏览器 Socks5 握手成功
	_, _ = localConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// D. 零泄漏双向流量接管
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(stream, localConn)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(localConn, stream)
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
	client := NewProxyClient(ClientConfig{
		LocalSocksAddr: "127.0.0.1:1080",
		RemoteUDPAddr:  "server_ip:8443",
		SecretToken:    getSecretToken(),
		ServerName:     "www.cisco.com",
	})

	client.Start()
}
