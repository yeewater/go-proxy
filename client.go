package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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
)

const (
	ProtocolVersion uint8  = 0x01
	CmdConnect      uint8  = 0x01
	HeaderLength    int    = 20
	TimeSlotSeconds int64  = 300
	FrameHeaderSize       = 4
	MaxPadding            = 512
)

type ClientConfig struct {
	LocalSocksAddr string
	RemoteAddr     string
	SecretSeed     []byte
	ServerName     string
}

type ProxyClient struct {
	cfg    ClientConfig
	tlsCfg *tls.Config
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

	serverConn, err := tls.Dial("tcp", c.cfg.RemoteAddr, c.tlsCfg)
	if err != nil {
		log.Printf("⚠️ 连接服务端失败: %v", err)
		return
	}

	token := deriveToken(c.cfg.SecretSeed, time.Now().Unix()/TimeSlotSeconds)

	header := make([]byte, HeaderLength)
	header[0] = ProtocolVersion
	header[1] = CmdConnect
	copy(header[2:18], token)
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

func getSecretSeed() []byte {
	if s := os.Getenv("PROXY_TOKEN"); len(s) == 16 {
		return []byte(s)
	}
	log.Println("⚠️ 环境变量 PROXY_TOKEN 未设置或长度不是 16，使用默认硬编码 Seed（仅供测试）")
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
		SecretSeed:     getSecretSeed(),
		ServerName:     "www.cisco.com",
	})

	log.Printf("当前 Token: %x", deriveToken(getSecretSeed(), time.Now().Unix()/TimeSlotSeconds))

	client.Start()
}
