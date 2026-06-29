package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

var secretToken []byte

func handleTunnel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/tunnel" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	token := r.Header.Get("X-Token")
	if subtle.ConstantTimeCompare([]byte(token), secretToken) != 1 {
		http.Error(w, "unauthorized", http.StatusForbidden)
		return
	}

	targetAddr := r.Header.Get("X-Target")
	if targetAddr == "" {
		http.Error(w, "missing target", http.StatusBadRequest)
		return
	}

	host, _, err := net.SplitHostPort(targetAddr)
	if err != nil {
		http.Error(w, "invalid target", http.StatusBadRequest)
		return
	}

	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		log.Printf("❌ 域名解析失败: %s", targetAddr)
		http.Error(w, "dns failed", http.StatusBadGateway)
		return
	}

	log.Printf("🔍 解析 %s -> %v", host, ips)
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			log.Printf("🛑 检测到内网地址: %s -> %s", targetAddr, ip)
			http.Error(w, "private ip", http.StatusForbidden)
			return
		}
	}

	log.Printf("🔗 正在 TCP 连接: %s", targetAddr)
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("❌ TCP 连接失败: %s, err: %v", targetAddr, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()
	log.Printf("✅ TCP 连接成功: %s", targetAddr)

	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	log.Printf("🔌 隧道已建立: %s", targetAddr)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, err := io.Copy(targetConn, r.Body)
		log.Printf("📤 隧道关闭(客户端→目标), 字节: %d, err: %v", n, err)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		n, err := io.Copy(w, targetConn)
		log.Printf("📥 隧道关闭(目标→客户端), 字节: %d, err: %v", n, err)
	}()

	wg.Wait()
	log.Printf("🔌 隧道已关闭: %s", targetAddr)
}

func getSecretToken() []byte {
	if token := os.Getenv("PROXY_TOKEN"); len(token) == 16 {
		return []byte(token)
	}
	log.Println("⚠️ 环境变量 PROXY_TOKEN 未设置或长度不是 16，使用默认硬编码 Token（仅供测试）")
	return []byte("my_secure_token!")
}

func loadOrGenerateCert(certFile, keyFile string) tls.Certificate {
	if _, err := os.Stat(certFile); err == nil {
		if cert, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
			log.Println("✅ 已加载 TLS 证书")
			return cert
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
	return cert
}

func main() {
	secretToken = getSecretToken()

	port := os.Getenv("PROXY_PORT")
	if port == "" {
		port = ":443"
	} else if port[0] != ':' {
		port = ":" + port
	}

	cert := loadOrGenerateCert("server.crt", "server.key")

	server := &http.Server{
		Addr: port,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
		},
		Handler: http.HandlerFunc(handleTunnel),
	}

	log.Printf("🚀 H2 代理服务端已就绪，监听 %s\n", port)
	log.Fatal(server.ListenAndServeTLS("", ""))
}
