package main

import (
	"bufio"
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
	"strings"
	"sync"
	"time"
)

const (
	ProtocolVersion uint8 = 0x01
	CmdConnect      uint8 = 0x01
	CmdPing         uint8 = 0x02
	CmdPong         uint8 = 0x03
	TimeSlotSeconds int64 = 300
	FrameHeaderSize       = 4
	MaxPadding            = 512
	MaxFrameSize          = 65535 // 防止恶意 fLen 导致超大内存分配

	// FlagRawMode: 由客户端在握手帧里显式声明本次隧道是否跳过 padding，
	// 不再用"目标端口是不是 443"去猜测，两端用同一个字段，不会出现误判。
	FlagRawMode uint8 = 0x01
)

type Config struct {
	ListenAddr   string
	SecretSeed   []byte
	FallbackAddr string
	FallbackHost string // fallbackSynthetic 用的 Host 头，应填本机 Caddy 实际配置的域名
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
	if cfg.FallbackHost == "" {
		cfg.FallbackHost = "localhost"
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
		// 只声明 http/1.1，刻意不支持 h2。
		// 原因：ALPN 协商出 h2 后，浏览器/curl 会用 HTTP/2 二进制帧发请求，
		// 这会被我们自己的 readPaddedFrame 误判成合法私有协议帧（巧合解析"成功"但内容是垃圾），
		// 同时 fallback 转发给 Caddy 时 Caddy 监听的是明文 h1，无法处理 h2 二进制帧，直接报错。
		// 服务端只声明 http/1.1，ALPN 协商阶段就不会走到 h2，从根上避免这个问题。
		NextProtos: []string{"http/1.1"},
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

// bufConn 包装原始连接，所有读取走 bufio.Reader，
// 这样 Peek 过的数据不会丢失，fallback 时可以把完整字节流转发出去。
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func newBufConn(c net.Conn) *bufConn {
	return &bufConn{Conn: c, r: bufio.NewReader(c)}
}

func (c *bufConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

func (s *Server) handleConn(rawConn net.Conn) {
	defer rawConn.Close()

	conn := newBufConn(rawConn)

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr, peekErr := conn.r.Peek(FrameHeaderSize)
	conn.SetReadDeadline(time.Time{})

	// 任何不能构成合法帧头的情况，统一走 fallback，
	// 此时缓冲区里的数据完全没有被消费，fallback 转发的是原始完整字节流。
	if peekErr != nil {
		s.fallback(conn)
		return
	}

	fLen := int(hdr[0])<<8 | int(hdr[1])
	dLen := int(hdr[2])<<8 | int(hdr[3])
	if fLen < dLen || dLen == 0 || fLen > MaxFrameSize {
		s.fallback(conn)
		return
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	frame, err := readPaddedFrame(conn)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		// 帧头已经被消费掉一部分，数据不完整，没法干净回落，直接断开。
		// 正常客户端不会触发这个分支；GFW 探测大概率在上面 peekErr 或长度校验就被拦下。
		return
	}

	// 协议帧最短长度: 1(version) + 1(msgType) + 16(token) + 2(targetLen) + 1(flags) = 21
	if len(frame) < 21 {
		s.fallbackSynthetic(rawConn)
		return
	}

	version := frame[0]
	msgType := frame[1]
	clientToken := frame[2:18]
	targetLen := binary.BigEndian.Uint16(frame[18:20])
	flags := frame[20]

	if version != ProtocolVersion || !checkToken(s.cfg.SecretSeed, clientToken) {
		// token 校验失败时，帧已经被完整读出，没法把"原始字节"丢给 Caddy 了。
		// 退而求其次：主动发一个干净的 GET 请求给 fallback，至少保证响应正常，
		// 不会把我们的私有二进制协议内容转发给 Caddy 导致 400。
		s.fallbackSynthetic(rawConn)
		return
	}

	switch msgType {
	case CmdPing:
		conn.Write([]byte{ProtocolVersion, CmdPong})
		return

	case CmdConnect:
		if targetLen < 3 || targetLen > 512 {
			return
		}
		if len(frame) < 21+int(targetLen) {
			return
		}
		rawMode := flags&FlagRawMode != 0
		s.establishTunnel(conn, string(frame[21:21+targetLen]), rawMode)

	default:
		return
	}
}

// fallback 用于 peek 阶段就判断出不是合法协议帧的连接：
// 缓冲区数据完全未被消费，可以把原始字节流原样转发给本地 Caddy。
func (s *Server) fallback(conn *bufConn) {
	addr := s.cfg.FallbackAddr
	if addr == "" {
		return
	}

	fbConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return
	}
	defer fbConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(fbConn, conn)
	}()
	go func() {
		defer wg.Done()
		io.Copy(conn, fbConn)
	}()
	wg.Wait()
}

// fallbackSynthetic 用于已经消费了私有协议帧、但 token 校验失败的场景。
// 此时没法把原始字节转发出去（已经被解析消费），改为主动构造一个干净的 HTTP 请求，
// 保证 fallback 服务器返回正常响应，而不是因为收到畸形/二进制数据返回 400。
func (s *Server) fallbackSynthetic(rawConn net.Conn) {
	addr := s.cfg.FallbackAddr
	if addr == "" {
		return
	}

	fbConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return
	}
	defer fbConn.Close()

	fmt.Fprintf(fbConn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", s.cfg.FallbackHost)
	io.Copy(rawConn, fbConn)
}

// establishTunnel 建立到目标地址的隧道。rawMode 由客户端在握手帧里显式声明，
// 不再用目标端口号推测是否需要 padding —— 两端用同一个 flag 字段，行为永远一致。
func (s *Server) establishTunnel(tlsConn net.Conn, targetAddr string, rawMode bool) {
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

	log.Printf("🔌 隧道已建立: %s (rawMode=%v)", targetAddr, rawMode)
	var wg sync.WaitGroup
	wg.Add(2)

	if rawMode {
		go func() {
			defer wg.Done()
			io.Copy(tlsConn, targetConn)
		}()
		go func() {
			defer wg.Done()
			io.Copy(targetConn, tlsConn)
		}()
	} else {
		go func() {
			defer wg.Done()
			relayWithPadding(tlsConn, targetConn)
		}()
		go func() {
			defer wg.Done()
			for {
				data, err := readPaddedFrame(tlsConn)
				if err != nil {
					return
				}
				if _, err := targetConn.Write(data); err != nil {
					return
				}
			}
		}()
	}

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
	if fLen < dLen || dLen == 0 || fLen > MaxFrameSize {
		return nil, errors.New("invalid frame")
	}

	frame := make([]byte, fLen)
	if _, err := io.ReadFull(r, frame); err != nil {
		return nil, err
	}
	return frame[:dLen], nil
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

// getSecretSeed 优先级: PROXY_TOKEN_FILE > PROXY_TOKEN 环境变量 > 硬编码默认值。
// 用文件而非环境变量传递密钥，可以避免密钥出现在 `ps aux` / `/proc/<pid>/environ` 等
// 容易被本机其他进程读到的地方。
func getSecretSeed() []byte {
	if path := os.Getenv("PROXY_TOKEN_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("Fatal: 无法读取 PROXY_TOKEN_FILE: %v", err)
		}
		s := strings.TrimSpace(string(data))
		if len(s) != 16 {
			log.Fatalf("Fatal: PROXY_TOKEN_FILE 内容长度必须是 16 字节，实际为 %d", len(s))
		}
		return []byte(s)
	}
	if s := os.Getenv("PROXY_TOKEN"); len(s) == 16 {
		return []byte(s)
	}
	log.Println("⚠️ 未设置 PROXY_TOKEN_FILE / PROXY_TOKEN，使用默认硬编码 Seed（仅供测试，生产环境务必修改）")
	return []byte("my_secure_token!")
}

func main() {
	seed := getSecretSeed()
	fallback := os.Getenv("FALLBACK")
	fallbackHost := os.Getenv("FALLBACK_HOST")

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
		FallbackHost: fallbackHost,
	})

	fmt.Printf("seed=%x, current token=%x\n", seed, deriveToken(seed, time.Now().Unix()/TimeSlotSeconds))

	server.Start()
}
