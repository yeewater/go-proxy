package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

const (
	ProtocolVersion uint8 = 0x01
	CmdConnect      uint8 = 0x01
	CmdPing         uint8 = 0x02
	CmdPong         uint8 = 0x03
	HeaderLength    int   = 20
)

type Config struct {
	ListenAddr  string
	SecretToken []byte
}

type Server struct {
	cfg Config
}

func NewServer(cfg Config) *Server {
	if len(cfg.SecretToken) != 16 {
		log.Fatalf("Fatal: SecretToken must be exactly 16 bytes")
	}
	return &Server{cfg: cfg}
}

func (s *Server) Start() {
	tcpListener, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		log.Fatalf("Failed to bind TCP port: %v", err)
	}
	defer tcpListener.Close()

	tlsConfig := s.generateTLSConfig()
	listener := tls.NewListener(tcpListener, tlsConfig)
	defer listener.Close()

	log.Printf("🚀 TCP+TLS 代理服务端已就绪，监听 %s\n", s.cfg.ListenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Listener down: %v", err)
			break
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	headerBuf := make([]byte, HeaderLength)
	if _, err := io.ReadFull(conn, headerBuf); err != nil {
		return
	}

	version := headerBuf[0]
	msgType := headerBuf[1]
	clientToken := headerBuf[2:18]
	targetLen := binary.BigEndian.Uint16(headerBuf[18:20])

	if version != ProtocolVersion {
		return
	}

	if subtle.ConstantTimeCompare(clientToken, s.cfg.SecretToken) != 1 {
		log.Printf("⚠️ 身份验证失败")
		return
	}

	switch msgType {
	case CmdPing:
		if _, err := conn.Write([]byte{ProtocolVersion, CmdPong}); err != nil {
			log.Printf("⚠️ Pong 写入失败: %v", err)
		}
		return

	case CmdConnect:
		if targetLen == 0 || targetLen > 512 {
			return
		}
		addrBuf := make([]byte, targetLen)
		if _, err := io.ReadFull(conn, addrBuf); err != nil {
			return
		}
		targetAddr := string(addrBuf)

		_ = conn.SetReadDeadline(time.Time{})
		s.establishTunnel(conn, targetAddr)

	default:
		return
	}
}

func (s *Server) establishTunnel(conn net.Conn, targetAddr string) {
	host, port, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return
	}

	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		log.Printf("❌ 域名解析失败: %s, err: %v", targetAddr, err)
		return
	}

	log.Printf("🔍 解析 %s -> %v", host, ips)

	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			log.Printf("🛑 检测到内网地址: %s -> %s", targetAddr, ip)
			return
		}
	}

	dialAddr := net.JoinHostPort(ips[0].String(), port)
	log.Printf("🔗 正在 TCP 连接: %s", dialAddr)
	targetConn, err := net.DialTimeout("tcp", dialAddr, 5*time.Second)
	if err != nil {
		log.Printf("❌ TCP 连接失败: %s, err: %v", dialAddr, err)
		return
	}
	defer targetConn.Close()
	log.Printf("✅ TCP 连接成功: %s", dialAddr)

	log.Printf("🔌 隧道已建立: %s", targetAddr)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, err := io.Copy(targetConn, conn)
		log.Printf("📤 隧道关闭(客户端→目标), 字节: %d, err: %v", n, err)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		n, err := io.Copy(conn, targetConn)
		log.Printf("📥 隧道关闭(目标→客户端), 字节: %d, err: %v", n, err)
	}()

	wg.Wait()
	log.Printf("🔌 隧道已关闭: %s", targetAddr)
}

func (s *Server) generateTLSConfig() *tls.Config {
	certFile := "server.crt"
	keyFile := "server.key"

	if cert, err := loadCertFromDisk(certFile, keyFile); err == nil {
		log.Println("✅ 已加载 TLS 证书")
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}

	log.Println("🔑 未找到 TLS 证书，正在生成自签名证书...")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	_ = os.WriteFile(certFile, certPEM, 0644)
	_ = os.WriteFile(keyFile, keyPEM, 0600)

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
}

func loadCertFromDisk(certFile, keyFile string) (tls.Certificate, error) {
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		return tls.Certificate{}, err
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(certFile, keyFile)
}

func getSecretToken() []byte {
	if token := os.Getenv("PROXY_TOKEN"); len(token) == 16 {
		return []byte(token)
	}
	log.Println("⚠️ 环境变量 PROXY_TOKEN 未设置或长度不是 16，使用默认硬编码 Token（仅供测试）")
	return []byte("my_secure_token!")
}

func main() {
	server := NewServer(Config{
		ListenAddr:  "0.0.0.0:443",
		SecretToken: getSecretToken(),
	})

	server.Start()
}
