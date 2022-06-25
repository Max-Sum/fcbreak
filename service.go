package fcbreak

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	reuse "github.com/libp2p/go-reuseport"
	"github.com/pires/go-proxyproto"
)

type ReqService struct {
	Service
	BindAddr  net.Addr
	cfg       ServiceConf
	clientCfg *ClientCommonConf
	client    *http.Client
	proxy     *httputil.ReverseProxy
	stopCh    chan (struct{})
}

func NewReqService(name string, cfg ServiceConf, clientCfg *ClientCommonConf) *ReqService {
	s := &ReqService{
		Service: Service{
			mutex:      sync.RWMutex{},
			Name:       name,
			RemoteAddr: fmt.Sprintf("%s:%d", cfg.RemoteAddr, cfg.RemotePort),
			Scheme:     cfg.Scheme,
		},
		cfg:       cfg,
		clientCfg: clientCfg,
		client:    &http.Client{},
		stopCh:    make(chan struct{}),
	}
	s.client.Transport = &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		Dial:                s.dialToServer,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: 0,
		MaxConnsPerHost:     0,
		IdleConnTimeout:     120 * time.Second,
		DisableKeepAlives:   false,
	}
	return s
}

type ServConn struct {
	*proxyproto.Conn
	header *proxyproto.Header
	dialer *net.Dialer
}

func (c *ServConn) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// establish forward link
	conn, err := c.dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if c.header != nil {
		_, err = c.header.WriteTo(conn)
		if err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

type ServAddr struct {
	net.Addr
	ProxyAddr net.Addr
}

func (c *ServConn) UnwrapConn() net.Conn {
	if tc, ok := c.Conn.TCPConn(); ok {
		return tc
	}
	if uc, ok := c.Conn.UDPConn(); ok {
		return uc
	}
	if uc, ok := c.Conn.UnixConn(); ok {
		return uc
	}
	return c.Conn
}

func (c *ServConn) RemoteAddr() net.Addr {
	return &ServAddr{
		Addr:      c.Conn.RemoteAddr(),
		ProxyAddr: c.UnwrapConn().RemoteAddr(),
	}
}

type servConnListener struct {
	*proxyproto.Listener
	clientCfg *ClientCommonConf
}

func (l *servConnListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	// Check Proxy Protocol
	pc, _ := conn.(*proxyproto.Conn)
	tc, _ := pc.TCPConn()
	remoteIP, _, err := net.SplitHostPort(tc.RemoteAddr().String())
	if err != nil {
		conn.Close()
		return nil, err
	}
	serverUrl, err := url.Parse(l.clientCfg.Server)
	if err != nil {
		return nil, err
	}
	serverIP, err := net.ResolveIPAddr("ip", serverUrl.Hostname())
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	if pc, ok := conn.(*proxyproto.Conn); ok {
		sc := &ServConn{
			Conn:   pc,
			dialer: &net.Dialer{},
			header: nil,
		}
		// Not from server
		if remoteIP != serverIP.String() {
			sc.header = pc.ProxyHeader()
		}
		// Write Proxy Protocol Header
		return sc, nil
	}
	return conn, nil
}

func (s *ReqService) Listen() (net.Listener, error) {
	l, err := reuse.Listen("tcp", fmt.Sprintf("%s:%d", s.cfg.BindAddr, s.cfg.BindPort))
	if err != nil {
		log.Fatal("Listen: ", err)
		return nil, err
	}
	s.mutex.Lock()
	s.l = &servConnListener{
		Listener: &proxyproto.Listener{
			Listener:          l,
			ReadHeaderTimeout: 30 * time.Second,
		},
		clientCfg: s.clientCfg,
	}
	s.mutex.Unlock()
	log.Printf("Service Listen: %s://%s", s.cfg.Scheme, l.Addr().String())
	return s.l, nil
}

func (s *ReqService) Serve(l net.Listener) (err error) {
	// Proxy HTTP
	if s.Scheme == "http" || s.Scheme == "https" {
		httpServ := &HTTPService{reqserv: s}
		return httpServ.Serve(l)
	}
	// Proxy TCP
	var conn net.Conn
	for {
		conn, err = s.l.Accept()
		if err != nil {
			log.Println("listener.Accept error:", err)
			break
		}
		go s.Handle(conn)
	}
	return err
}

func (s *ReqService) ListenAndServe() error {
	l, err := s.Listen()
	if err != nil {
		return err
	}
	return s.Serve(l)
}

// Handle raw connection
func (s *ReqService) Handle(conn net.Conn) error {
	defer conn.Close()
	dialFn := (&net.Dialer{}).DialContext
	if sc, ok := conn.(*ServConn); ok {
		dialFn = sc.DialContext
	}
	localAddr := fmt.Sprintf("%s:%d", s.cfg.LocalAddr, s.cfg.LocalPort)
	rconn, err := dialFn(context.Background(), "tcp", localAddr)
	if err != nil {
		return err
	}
	defer rconn.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		_, err := io.Copy(conn, rconn)
		if cw, ok := conn.(CloseWriter); ok {
			cw.CloseWrite()
		}
		if cr, ok := rconn.(CloseReader); ok {
			cr.CloseRead()
		}
		if err != nil && err != io.EOF {
			log.Printf("copy err %v\n", err)
		}
		wg.Done()
	}()
	_, err = io.Copy(rconn, conn)
	if cw, ok := rconn.(CloseWriter); ok {
		cw.CloseWrite()
	}
	if cr, ok := conn.(CloseReader); ok {
		cr.CloseRead()
	}
	wg.Wait()
	if err != nil && err != io.EOF {
		log.Printf("copy err %v\n", err)
	}
	return err
}

func (s *ReqService) Close() error {
	if s.l != nil {
		s.mutex.Lock()
		defer s.mutex.Unlock()
		if s.l != nil {
			err := s.l.Close()
			s.l = nil
			return err
		}
	}
	return nil
}

func (s *ReqService) dialToServer(network string, addr string) (net.Conn, error) {
	return reuse.Dial("tcp", s.BindAddr.String(), addr)
}

func (s *ReqService) register() error {
	addr := fmt.Sprintf("%s/services", s.clientCfg.Server)
	str, err := json.Marshal(s.Service)
	if err != nil {
		return err
	}
	b := bytes.NewBuffer(str)
	req, err := http.NewRequest("POST", addr, b)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	by, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New("Register [" + s.Name + "] error: " + string(by))
	}
	return json.Unmarshal(by, &s.Service)
}

func (s *ReqService) refresh() error {
	addr := fmt.Sprintf("%s/services/%s", s.clientCfg.Server, s.Name)
	str, err := json.Marshal(s.Service)
	if err != nil {
		return err
	}
	b := bytes.NewBuffer(str)
	req, err := http.NewRequest("PUT", addr, b)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	by, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New("Refresh [" + s.Name + "] error: " + string(by))
	}
	return json.Unmarshal(by, &s.Service)
}

func (s *ReqService) delete() error {
	addr := fmt.Sprintf("%s/services/%s", s.clientCfg.Server, s.Name)
	req, err := http.NewRequest("DELETE", addr, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		by, _ := io.ReadAll(resp.Body)
		return errors.New("Delete [" + s.Name + "] error: " + string(by))
	}
	return nil
}

func (s *ReqService) refreshTimer() {
	for {
		select {
		case <-time.After(time.Duration(s.clientCfg.HeartbeatInterval) * time.Second):
			s.refresh()
		case <-s.stopCh:
			return
		}
	}
}

func (s *ReqService) Start() error {
	l, err := s.Listen()
	if err != nil {
		return err
	}
	s.BindAddr = l.Addr()
	if err := s.register(); err != nil {
		return err
	}
	go s.refreshTimer()
	go s.Serve(l)
	return nil
}

func (s *ReqService) Stop() error {
	s.delete()
	s.stopCh <- struct{}{}
	return s.Close()
}
