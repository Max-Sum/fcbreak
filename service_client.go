package fcbreak

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	reuse "github.com/libp2p/go-reuseport"
	proxyproto "github.com/pires/go-proxyproto"
)

func NewService(name string, cfg *ServiceConf) Service {
	var s Service
	switch strings.ToLower(cfg.Scheme) {
	case "tcp":
		s = NewTCPService(name, cfg)
	case "http":
		fallthrough
	case "https":
		s = NewHTTPService(name, cfg)
	default:
		log.Printf("scheme %s is not supported", cfg.Scheme)
	}
	return s
}

type Service interface {
	Serve(net.Listener) error
	Shutdown(context.Context) error
	GetCfg() *ServiceConf
	GetInfo() *ServiceInfo
}

// listenForService listen for common connections
func listenForService(s Service) (net.Listener, error) {
	dl, err := reuse.Listen("tcp", fmt.Sprintf("%s:%d", s.GetCfg().BindAddr, s.GetCfg().BindPort))
	if err != nil {
		log.Fatal("Listen: ", err)
		return nil, err
	}
	log.Printf("Service [%s] Listen: %s://%s", s.GetInfo().Name, s.GetInfo().Scheme, dl.Addr().String())
	return &svcInitListener{Listener: dl, isReflected: false}, nil
}

// listenProxyForService is listen for proxy protocol connections from relector
func listenProxyForService(s Service) (net.Listener, error) {
	l, err := reuse.Listen("tcp", fmt.Sprintf("%s:0", s.GetCfg().BindAddr))
	if err != nil {
		log.Fatal("Listen: ", err)
		return nil, err
	}
	log.Printf("Service [%s] Listen: %s+proxyproto://%s", s.GetInfo().Name, s.GetInfo().Scheme, l.Addr().String())
	return &svcInitListener{Listener: &proxyproto.Listener{Listener: l}, isReflected: true}, nil
}

type svcInitListener struct {
	net.Listener
	isReflected bool
	once        sync.Once
}

type svcInitConn struct {
	net.Conn
	IsReflected bool // Indicates if the connection is via server
}

func (l *svcInitListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return svcInitConn{c, l.isReflected}, nil
}

// withStand multiple Closes
func (l *svcInitListener) Close() (err error) {
	l.once.Do(func() {
		err = l.Listener.Close()
	})
	return
}
