package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
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

	TimeSlotSeconds int64 = 300
	FrameHeaderSize       = 4
	MaxPadding            = 512
)

type Config struct {
	ListenAddr   string
	SecretSeed   []byte
	FallbackAddr string
}

type Server struct {
	cfg Config
}

func NewServer(cfg Config) *Server {
	if len(cfg.SecretSeed) != 16 {
		log.Fatalf("Fatal: SecretSeed must be exactly 16 bytes")
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "0.0.0.0:443"
	}
	return &Server{cfg: cfg}
}

func deriveTokens(seed []byte) [][]byte {
	slot := time.Now().Unix() / TimeSlotSeconds
	return [][]byte{
		deriveToken(seed, slot),
		deriveToken(seed, slot-1),
		deriveToken(seed, slot+1),
	}
}

func deriveToken(seed []byte, slot int64) []byte {
	mac := hmac.New(sha256.New, seed)
	mac.Write(binary.BigEndian.AppendUint64(nil, uint64(slot)))
	return mac.Sum(nil)[:16]
}

func checkToken(seed []byte, received []byte) bool {
	for _, t := range deriveTokens(seed) {
		if subtle.ConstantTimeCompare(received, t) == 1 {
			return true
		}
	}
	return false
}

func (s *Server) Start() {
	tcpListener, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		log.Fatalf("Failed to bind port: %v", err)
	}
	defer tcpListener.Close()

	tlsConfig := &tls.Config{
		Certificates: s.loadCertificates(),
		NextProtos:   []string{"http/1.1"},
	}
	listener := tls.NewListener(tcpListener, tlsConfig)
	defer listener.Close()

	log.Printf("🚀 服务端已就绪，监听 %s\n", s.cfg.ListenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Listener down: %v", err)
			break
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(tlsConn net.Conn) {
	defer tlsConn.Close()

	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))

	headerBuf := make([]byte, HeaderLength)
	_, err := io.ReadFull(tlsConn, headerBuf)
	if err != nil {
		tlsConn.SetReadDeadline(time.Time{})
		s.fallback(tlsConn, nil)
		return
	}
	tlsConn.SetReadDeadline(time.Time{})

	version := headerBuf[0]
	msgType := headerBuf[1]
	clientToken := headerBuf[2:18]
	targetLen := binary.BigEndian.Uint16(headerBuf[18:20])

	if version != ProtocolVersion || !checkToken(s.cfg.SecretSeed, clientToken) {
		buf := make([]byte, 0, HeaderLength)
		buf = append(buf, headerBuf...)
		s.fallback(tlsConn, buf)
		return
	}

	switch msgType {
	case CmdPing:
		tlsConn.Write([]byte{ProtocolVersion, CmdPong})
		return

	case CmdConnect:
		if targetLen == 0 || targetLen > 512 {
			return
		}
		addrBuf := make([]byte, targetLen)
		if _, err := io.ReadFull(tlsConn, addrBuf); err != nil {
			return
		}
		s.establishTunnel(tlsConn, string(addrBuf))

	default:
		return
	}
}

func (s *Server) fallback(tlsConn net.Conn, prefix []byte) {
	addr := s.cfg.FallbackAddr
	if addr == "" {
		return
	}

	fbConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return
	}
	defer fbConn.Close()

	if len(prefix) > 0 {
		fbConn.Write(prefix)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(fbConn, tlsConn)
	}()
	go func() {
		defer wg.Done()
		io.Copy(tlsConn, fbConn)
	}()
	wg.Wait()
}

func (s *Server) establishTunnel(tlsConn net.Conn, targetAddr string) {
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
		relayWithPadding(tlsConn, targetConn)
	}()

	go func() {
		defer wg.Done()
		relayWithPadding(targetConn, tlsConn)
	}()

	wg.Wait()
	log.Printf("🔌 隧道已关闭: %s", targetAddr)
}

func relayWithPadding(dst io.Writer, src io.Reader) {
	buf := make([]byte, 16384)
	for {
		n, err := src.Read(buf)
		if err != nil {
			return
		}
		if err := writePaddedFrame(dst, buf[:n]); err != nil {
			return
		}
	}
}

func writePaddedFrame(w io.Writer, data []byte) error {
	dLen := len(data)
	pLen := 0
	if MaxPadding > 0 {
		var b [1]byte
		rand.Read(b[:])
		pLen = int(b[0]) % (MaxPadding + 1)
	}
	fLen := dLen + pLen

	header := []byte{
		byte(fLen >> 8), byte(fLen),
		byte(dLen >> 8), byte(dLen),
	}

	frame := make([]byte, FrameHeaderSize+fLen)
	copy(frame[:FrameHeaderSize], header)
	copy(frame[FrameHeaderSize:], data)
	if pLen > 0 {
		rand.Read(frame[FrameHeaderSize+dLen:])
	}

	_, err := w.Write(frame)
	return err
}

func readPaddedFrame(r io.Reader) ([]byte, error) {
	hdr := make([]byte, FrameHeaderSize)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	fLen := int(hdr[0])<<8 | int(hdr[1])
	dLen := int(hdr[2])<<8 | int(hdr[3])
	if fLen < dLen || dLen == 0 {
		return nil, errors.New("invalid frame")
	}

	frame := make([]byte, fLen)
	if _, err := io.ReadFull(r, frame); err != nil {
		return nil, err
	}
	return frame[:dLen], nil
}

type paddedConn struct {
	net.Conn
}

func (c *paddedConn) Read(b []byte) (int, error) {
	data, err := readPaddedFrame(c.Conn)
	if err != nil {
		return 0, err
	}
	return copy(b, data), nil
}

func (c *paddedConn) Write(b []byte) (int, error) {
	err := writePaddedFrame(c.Conn, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (s *Server) loadCertificates() []tls.Certificate {
	certFile := "server.crt"
	keyFile := "server.key"
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err == nil {
		log.Println("✅ 已加载 TLS 证书")
		return []tls.Certificate{cert}
	}

	log.Println("🔑 未找到 TLS 证书，正在生成自签名证书...")
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	os.WriteFile(certFile, certPEM, 0644)
	os.WriteFile(keyFile, keyPEM, 0600)
	cert, _ = tls.X509KeyPair(certPEM, keyPEM)
	return []tls.Certificate{cert}
}

func getSecretSeed() []byte {
	if s := os.Getenv("PROXY_TOKEN"); len(s) == 16 {
		return []byte(s)
	}
	log.Println("⚠️ 环境变量 PROXY_TOKEN 未设置或长度不是 16，使用默认硬编码 Seed（仅供测试）")
	return []byte("my_secure_token!")
}

func main() {
	seed := getSecretSeed()
	fallback := os.Getenv("FALLBACK")

	if fallback == "" {
		log.Println("ℹ️ FALLBACK 未设置，非法连接直接断开")
	} else {
		log.Printf("ℹ️ FALLBACK = %s，非法连接将转发至此地址", fallback)
	}

	port := os.Getenv("PROXY_PORT")
	if port == "" {
		port = ":443"
	} else if port[0] != ':' {
		port = ":" + port
	}

	server := NewServer(Config{
		ListenAddr:   port,
		SecretSeed:   seed,
		FallbackAddr: fallback,
	})

	fmt.Printf("seed=%x, current token=%x\n", seed, deriveToken(seed, time.Now().Unix()/TimeSlotSeconds))

	server.Start()
}
