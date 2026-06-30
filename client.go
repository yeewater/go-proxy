package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

const (
	ProtocolVersion uint8  = 0x01
	CmdConnect      uint8  = 0x01
	TimeSlotSeconds int64  = 300
	FrameHeaderSize        = 4
	MaxPadding             = 512

	// FlagRawMode: 显式声明本次隧道跳过 padding（目标本身已是 TLS 流量，
	// 双重加密带来的开销收益不大）。两端必须用同一套规则判断，不能各猜各的，
	// 否则一边加 padding 一边不加会直接导致帧解析错乱。
	FlagRawMode uint8 = 0x01
)

type ClientConfig struct {
	LocalSocksAddr string
	RemoteAddr     string
	SecretSeed     []byte
	ServerName     string
}

type ProxyClient struct {
	cfg ClientConfig
}

func NewProxyClient(cfg ClientConfig) *ProxyClient {
	return &ProxyClient{cfg: cfg}
}

func deriveToken(seed []byte, slot int64) []byte {
	mac := hmac.New(sha256.New, seed)
	mac.Write(binary.BigEndian.AppendUint64(nil, uint64(slot)))
	return mac.Sum(nil)[:16]
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

	tcpConn, err := net.DialTimeout("tcp", c.cfg.RemoteAddr, 5*time.Second)
	if err != nil {
		log.Printf("⚠️ 连接服务端失败: %v", err)
		return
	}

	// 显式指定 ALPN，与服务端 NextProtos: []string{"http/1.1"} 对齐。
	// 故意不声明 h2 支持：协商出 h2 会导致后续流量变成 HTTP/2 二进制帧，
	// 被自定义协议层和 fallback 的 Caddy 都无法正确处理。
	utlsConfig := &utls.Config{
		InsecureSkipVerify: true,
		ServerName:         c.cfg.ServerName,
		NextProtos:         []string{"http/1.1"},
	}
	serverConn := utls.UClient(tcpConn, utlsConfig, utls.HelloChrome_Auto)
	if err := serverConn.Handshake(); err != nil {
		tcpConn.Close()
		log.Printf("⚠️ TLS 握手失败: %v", err)
		return
	}

	token := deriveToken(c.cfg.SecretSeed, time.Now().Unix()/TimeSlotSeconds)

	// rawMode 由目标端口显式判断一次，写入协议帧的 flags 字段，
	// 服务端不再自己猜端口，而是直接读这个字段 —— 两端永远同步。
	var flags uint8
	if targetPort == 443 {
		flags |= FlagRawMode
	}

	handshake := make([]byte, 0, 2+16+2+1+len(targetAddr))
	handshake = append(handshake, ProtocolVersion, CmdConnect)
	handshake = append(handshake, token...)
	handshake = append(handshake, byte(len(targetAddr)>>8), byte(len(targetAddr)))
	handshake = append(handshake, flags)
	handshake = append(handshake, []byte(targetAddr)...)

	if err := writePaddedFrame(serverConn, handshake); err != nil {
		serverConn.Close()
		return
	}

	_, _ = localConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	var wg sync.WaitGroup
	wg.Add(2)

	rawMode := flags&FlagRawMode != 0
	if rawMode {
		go func() {
			defer wg.Done()
			io.Copy(serverConn, localConn)
		}()
		go func() {
			defer wg.Done()
			io.Copy(localConn, serverConn)
		}()
	} else {
		go func() {
			defer wg.Done()
			relayWithPadding(serverConn, localConn)
		}()
		go func() {
			defer wg.Done()
			for {
				data, err := readPaddedFrame(serverConn)
				if err != nil {
					return
				}
				if _, err := localConn.Write(data); err != nil {
					return
				}
			}
		}()
	}

	wg.Wait()
	serverConn.Close()
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

// getSecretSeed 优先级: PROXY_TOKEN_FILE > PROXY_TOKEN 环境变量 > 硬编码默认值。
func getSecretSeed() []byte {
	if path := os.Getenv("PROXY_TOKEN_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("Fatal: 无法读取 PROXY_TOKEN_FILE: %v", err)
		}
		s := string(data)
		// 去除可能的换行符
		for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
			s = s[:len(s)-1]
		}
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
	addr := os.Getenv("PROXY_SERVER")
	if addr == "" {
		addr = "server_ip:443"
	}

	sni := os.Getenv("PROXY_SNI")
	if sni == "" {
		sni = "www.cisco.com"
	}

	client := NewProxyClient(ClientConfig{
		LocalSocksAddr: "127.0.0.1:1080",
		RemoteAddr:     addr,
		SecretSeed:     getSecretSeed(),
		ServerName:     sni,
	})

	log.Printf("当前 Token: %x", deriveToken(getSecretSeed(), time.Now().Unix()/TimeSlotSeconds))

	client.Start()
}
