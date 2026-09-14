package httpengine

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

const (
	defaultTorProxyAddr = "127.0.0.1:9050"
	defaultTorCtrlAddr  = "127.0.0.1:9051"
)

type TorConfig struct {
	ProxyAddr string
	CtrlAddr  string
	Password  string
}

type TorDialer struct {
	config  *TorConfig
	dialer  proxy.ContextDialer
	enabled bool
}

func DefaultTorConfig() *TorConfig {
	return &TorConfig{
		ProxyAddr: defaultTorProxyAddr,
		CtrlAddr:  defaultTorCtrlAddr,
	}
}

func NewTorDialer(cfg *TorConfig) (*TorDialer, error) {
	if cfg == nil {
		cfg = DefaultTorConfig()
	}

	auth := &proxy.Auth{}
	dialer, err := proxy.SOCKS5("tcp", cfg.ProxyAddr, auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to create Tor SOCKS5 dialer: %w", err)
	}

	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("Tor SOCKS5 dialer does not support DialContext")
	}

	return &TorDialer{
		config:  cfg,
		dialer:  contextDialer,
		enabled: true,
	}, nil
}

func (td *TorDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return td.dialer.DialContext(ctx, network, addr)
}

func (td *TorDialer) Transport() *http.Transport {
	return &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext:         td.DialContext,
	}
}

func (td *TorDialer) RenewIdentity() error {
	conn, err := net.DialTimeout("tcp", td.config.CtrlAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to Tor control port: %w", err)
	}
	defer conn.Close()

	if td.config.Password != "" {
		fmt.Fprintf(conn, "AUTHENTICATE \"%s\"\r\n", td.config.Password)
	} else {
		fmt.Fprintf(conn, "AUTHENTICATE \"\"\r\n")
	}

	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString('\n')
	if err != nil || !isTorOK(resp) {
		return fmt.Errorf("Tor authentication failed: %s", strings.TrimSpace(resp))
	}

	fmt.Fprintf(conn, "SIGNAL NEWNYM\r\n")
	resp, err = reader.ReadString('\n')
	if err != nil || !isTorOK(resp) {
		return fmt.Errorf("Tor NEWNYM signal failed: %s", strings.TrimSpace(resp))
	}

	return nil
}

func (td *TorDialer) IsEnabled() bool {
	return td.enabled
}

func CheckTorRunning(proxyAddr string) bool {
	if proxyAddr == "" {
		proxyAddr = defaultTorProxyAddr
	}

	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func isTorOK(resp string) bool {
	return len(resp) >= 3 && resp[:3] == "250"
}