package fcbreak

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
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
	proxy     *httputil.ReverseProxy
}

func NewReqService(name string, cfg ServiceConf, clientCfg *ClientCommonConf) *ReqService {
	return &ReqService{
		Service: Service{
			mutex:      sync.RWMutex{},
			Name:       name,
			RemoteAddr: fmt.Sprintf("%s:%d", cfg.RemoteAddr, cfg.RemotePort),
			Scheme:     cfg.Scheme,
		},
		cfg:       cfg,
		clientCfg: clientCfg,
	}
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
	serverIP, err := net.ResolveIPAddr("ip", l.clientCfg.ServerAddr)
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
		u := &url.URL{
			Scheme: "http",
			Host:   fmt.Sprintf("%s:%d", s.cfg.LocalAddr, s.cfg.LocalPort),
		}
		if s.cfg.TLSBackend {
			u.Scheme = "https"
		}
		s.proxy = httputil.NewSingleHostReverseProxy(u)
		s.proxy.ModifyResponse = s.ModifyResponse
		serv := &http.Server{
			ConnContext: SaveConnInContext,
			Handler:     s,
		}
		if s.Scheme == "http" {
			return serv.Serve(l)
		}

		return serv.ServeTLS(l, s.cfg.HTTPServiceConf.TLSCert, s.cfg.HTTPServiceConf.TLSKey)
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

func (s *ReqService) proxiedFromServer(r *http.Request) bool {
	serverIP, err := net.ResolveIPAddr("ip", s.clientCfg.ServerAddr)
	if err != nil {
		return false
	}
	if addr, ok := GetConn(r).RemoteAddr().(*ServAddr); ok {
		proxyIP, _, err := net.SplitHostPort(addr.ProxyAddr.String())
		if err != nil {
			return false
		}
		return proxyIP == serverIP.String()
	}
	return false
}

func (s *ReqService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u := r.URL
	if r.TLS == nil {
		u.Scheme = "http"
	} else {
		u.Scheme = "https"
	}
	// Proxied from Server
	u.Host, _ = s.exposedAddr()
	if s.proxiedFromServer(r) && (!s.cfg.AltSvc || !SupportAltSvc(r.UserAgent())) {
		// Redirect with Cache Control
		h := w.Header()
		_, hadCT := h["Content-Type"]
		h.Set("Cache-Control", fmt.Sprintf("max-age=%ds", int(s.cfg.HTTPServiceConf.CacheTime)))
		h.Set("Location", u.String())
		if !hadCT && (r.Method == "GET" || r.Method == "HEAD") {
			h.Set("Content-Type", "text/html; charset=utf-8")
		}
		w.WriteHeader(http.StatusPermanentRedirect)
		// Shouldn't send the body for POST or HEAD; that leaves GET.
		if !hadCT && r.Method == "GET" {
			body := "<a href=\"" + u.String() + "\">Redirected</a>.\n"
			fmt.Fprintln(w, body)
		}
		return
	}
	// transparent
	s.proxy.ServeHTTP(w, r)
}

func (s *ReqService) exposedAddr() (string, error) {
	if len(s.cfg.NIPDomain) == 0 {
		return s.ExposedAddr, nil
	}
	host, port, err := net.SplitHostPort(s.ExposedAddr)
	if err != nil {
		return s.ExposedAddr, err
	}
	host = strings.ReplaceAll(host, ".", "-") + "." + s.cfg.NIPDomain
	return host + ":" + port, nil
}

func (s *ReqService) ModifyResponse(r *http.Response) error {
	if !s.cfg.AltSvc || !SupportAltSvc(r.Request.UserAgent()) {
		return nil
	}
	addr, err := s.exposedAddr()
	if err != nil {
		return err
	}
	if u, ok := r.Request.Header["Alt-Used"]; ok && u[0] == addr {
		return nil
	}
	altsvc := fmt.Sprintf("h2=\"%s\"; ma=%d; persist=1", addr, s.cfg.CacheTime)
	r.Header.Add("Alt-Svc", altsvc)
	return nil
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
