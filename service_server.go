package fcbreak

import (
	"io"
	"log"
	"net"
	"sync"

	"github.com/pires/go-proxyproto"
)

type ServiceInfo struct {
	Name        string `json:"name" binding:"required"`
	RemoteAddr  string `json:"remote_addr" binding:"required"`
	ExposedAddr string `json:"exposed_addr,omitempty"` // address for direct connection
	ProxyAddr   string `json:"proxy_addr,omitempty"`   // address for proxy_protocol
	Scheme      string `json:"scheme" binding:"required"`
}

// ServiceReflector is the implementation on Server-side.
type ServiceReflector struct {
	*ServiceInfo
	l     net.Listener
	mutex sync.RWMutex
}

func DefaultServiceReflector() *ServiceReflector {
	return &ServiceReflector{
		ServiceInfo: &ServiceInfo{},
		l:           nil,
		mutex:       sync.RWMutex{},
	}
}

// Handle an client request
func (r *ServiceReflector) Handle(conn net.Conn) error {
	defer conn.Close()
	r.mutex.RLock()
	addr := r.ExposedAddr
	useProxyProto := r.ProxyAddr != ""
	if useProxyProto {
		addr = r.ProxyAddr
	}
	r.mutex.RUnlock()
	target, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	rconn, err := net.DialTCP("tcp", nil, target)
	if err != nil {
		return err
	}
	defer rconn.Close()
	if useProxyProto {
		// Write Proxy Scheme Header
		header := proxyproto.HeaderProxyFromAddrs(2, rconn.RemoteAddr(), target)
		_, err = header.WriteTo(rconn)
		if err != nil {
			return err
		}
	}
	// Proxy TCP Link
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		_, err := io.Copy(conn, rconn)
		if cw, ok := conn.(CloseWriter); ok {
			cw.CloseWrite()
		}
		rconn.CloseRead()
		if err != nil && err != io.EOF {
			log.Printf("copy err %v\n", err)
		}
		wg.Done()
	}()
	_, err = io.Copy(rconn, conn)
	if cr, ok := conn.(CloseReader); ok {
		cr.CloseRead()
	}
	rconn.CloseWrite()
	wg.Wait()
	if err != nil && err != io.EOF {
		log.Printf("copy err %v\n", err)
		return err
	}
	return nil
}

func (r *ServiceReflector) Listen() error {
	if r.l != nil {
		return nil
	}
	l, err := net.Listen("tcp", r.RemoteAddr)
	if err != nil {
		log.Printf("Listen Error: %v", err)
		return err
	}
	r.l = l
	log.Printf("Service [%s] Listen: %s://%s\n", r.Name, r.Scheme, r.RemoteAddr)
	return nil
}

func (r *ServiceReflector) Serve() {
	if r.l == nil {
		return
	}
	for {
		conn, err := r.l.Accept()
		if err != nil {
			log.Println("listener.Accept error:", err)
			break
		}
		go r.Handle(conn)
	}
	// Clear running bit
	if r.l != nil {
		r.l = nil
	}
}
func (r *ServiceReflector) Stop() error {
	if r.Running() {
		if err := r.l.Close(); err != nil {
			return err
		}
		r.l = nil
	}
	return nil
}

func (r *ServiceReflector) Running() bool {
	return r.l != nil
}
