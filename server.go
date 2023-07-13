package fcbreak

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	dissector "github.com/go-gost/tls-dissector"
)

var (
	ErrorServiceNotFound = errors.New("Service is not found")
)

// getServiceInfoForOutput filters fields for output
func getServiceInfoForOutput(svc *ServiceReflector) *ServiceInfo {
	info := svc.GetServiceInfo()
	info.ProxyAddr = ""
	return info
}

type Server struct {
	User          string
	Pass          string
	mutex         sync.RWMutex
	httpServer    *http.Server
	shutdown      chan struct{}
	reflectors    map[string]*ServiceReflector
	httpMux       map[string]*ServiceReflector
	httpsMux      map[string]*ServiceReflector
	connGroup     sync.WaitGroup
	listenerGroup sync.WaitGroup
	conns         map[*net.Conn]struct{}
	listeners     map[*net.Listener]struct{}
}

func NewServer(user, pass string, tlsConf *tls.Config) *Server {
	s := &Server{
		User:       user,
		Pass:       pass,
		mutex:      sync.RWMutex{},
		shutdown:   make(chan struct{}),
		reflectors: map[string]*ServiceReflector{},
		httpMux:    map[string]*ServiceReflector{},
		httpsMux:   map[string]*ServiceReflector{},
		conns:      make(map[*net.Conn]struct{}),
		listeners:  make(map[*net.Listener]struct{}),
	}

	router := gin.Default()
	s.httpServer = &http.Server{
		Handler:     router,
		IdleTimeout: 30 * time.Minute,
		TLSConfig:   tlsConf,
		ConnContext: saveConnInContext,
		ConnState:   s.connState,
	}
	var r *gin.RouterGroup
	if s.User != "" && s.Pass != "" {
		r = router.Group("/", gin.BasicAuth(gin.Accounts{s.User: s.Pass}))
	} else {
		r = router.Group("/")
	}

	r.GET("/services", s.GetServices)
	r.GET("/services/:name", s.GetServiceByName)
	r.POST("/services", s.PostService)
	r.PUT("/services/:name", s.PutService)
	r.PUT("/services/:name/addr", s.PutServiceExposedAddr)
	r.PUT("/services/:name/proxy_addr", s.PutServiceProxyAddr)
	r.DELETE("/services/:name", s.DeleteService)

	return s
}

// not thread-safe!
func (s *Server) addService(svc *ServiceInfo) (*ServiceInfo, error) {
	if r, found := s.reflectors[svc.Name]; found {
		info := r.GetServiceInfo()
		return info, errors.New("service [" + svc.Name + "] already exists")
	}
	if svc.Scheme == "http" {
		for _, host := range svc.Hostnames {
			if len(host) == 0 {
				return svc, errors.New("empty host is illegal")
			}
			if ! verifyHostname(host) {
				return svc, errors.New("host is illegal, host can contains no or one * at the beginning or at the ending")
			}
			if r, ok := s.httpMux[host]; ok {
				info := r.GetServiceInfo()
				return svc, errors.New("service [" + info.Name + "] already registered for the hostname: " + host)
			}
		}
	}
	if svc.Scheme == "https" {
		for _, host := range svc.Hostnames {
			if len(host) == 0 {
				return svc, errors.New("empty host is illegal")
			}
			if r, ok := s.httpsMux[host]; ok {
				info := r.GetServiceInfo()
				return svc, errors.New("service [" + info.Name + "] already registered for the hostname: " + host)
			}
		}
	}
	r := NewServiceReflector(svc)
	if len(r.info.RemoteAddr) > 0 {
		if err := r.Listen(); err != nil {
			return nil, err
		}
		go r.Serve()
	}
	s.reflectors[svc.Name] = r
	if svc.Scheme == "http" {
		for _, host := range svc.Hostnames {
			s.httpMux[host] = r
		}
	} else if svc.Scheme == "https" {
		for _, host := range svc.Hostnames {
			s.httpsMux[host] = r
		}
	}
	return svc, nil
}

// not thread-safe!
func (s *Server) updateService(ctx context.Context, name string, svc *ServiceInfo) (*ServiceInfo, error) {
	if oldSvc, found := s.reflectors[name]; found {
		if name != svc.Name {
			log.Printf("Rename Service: [%s] -> [%s]", name, svc.Name)
			oldSvc.Rename(name)
			delete(s.reflectors, name)
			s.reflectors[svc.Name] = oldSvc
		}
		oldInfo := oldSvc.GetServiceInfo()
		// Need to restart
		if oldInfo.RemoteAddr != svc.RemoteAddr ||
			oldInfo.Scheme != svc.Scheme ||
			!reflect.DeepEqual(oldInfo.Hostnames, svc.Hostnames) {
			log.Printf("Update Service: [%s]", svc.Name)
			if err := s.delService(ctx, oldInfo.Name); err != nil {
				return nil, err
			}
			return s.addService(svc)
		}
		// Update Address
		if oldInfo.ExposedAddr != svc.ExposedAddr || oldInfo.ProxyAddr != svc.ProxyAddr {
			log.Printf("Update Service Address: [%s]", svc.Name)
			oldSvc.UpdateAddr(&svc.ExposedAddr, &svc.ProxyAddr)
		}
		return oldSvc.GetServiceInfo(), nil
	}
	return nil, ErrorServiceNotFound
}

// not thread-safe!
func (s *Server) delService(ctx context.Context, name string) error {
	if svc, found := s.reflectors[name]; found {
		svc.Stop(ctx)
		info := svc.GetServiceInfo()
		if info.Scheme == "http" {
			for _, host := range info.Hostnames {
				delete(s.httpMux, host)
			}
		} else if info.Scheme == "https" {
			for _, host := range info.Hostnames {
				delete(s.httpsMux, host)
			}
		}
		delete(s.reflectors, name)
		return nil
	}
	return ErrorServiceNotFound
}

func (s *Server) labelConn(req *http.Request, svcName string) {
	conn := getConnUnwarpTLS(req)
	if wc, ok := conn.(*wrappedConn); ok {
		wc.svc = &svcName
	}
}

func (s *Server) AddService(svc *ServiceInfo) (*ServiceInfo, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.addService(svc)
}

func (s *Server) UpdateService(ctx context.Context, name string, svc *ServiceInfo) (*ServiceInfo, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.updateService(ctx, name, svc)
}

func (s *Server) DelService(ctx context.Context, name string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.delService(ctx, name)
}

func (s *Server) GetServices(c *gin.Context) {
	svcs := make(map[string]*ServiceInfo)
	s.mutex.RLock()
	for n, r := range s.reflectors {
		svcs[n] = getServiceInfoForOutput(r)
	}
	s.mutex.RUnlock()
	c.IndentedJSON(http.StatusOK, svcs)
}

func (s *Server) GetServiceByName(c *gin.Context) {
	name := c.Param("name")
	s.mutex.RLock()
	r, ok := s.reflectors[name]
	s.mutex.RUnlock()
	if !ok {
		c.IndentedJSON(http.StatusNotFound, gin.H{"message": "service not found"})
		return
	}
	c.IndentedJSON(http.StatusOK, getServiceInfoForOutput(r))
}

func (s *Server) PostService(c *gin.Context) {
	svc := &ServiceInfo{}
	if err := c.BindJSON(&svc); err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	svc.ExposedAddr = c.Request.RemoteAddr
	log.Printf("Register Service [%s]: %s://%s -> %s://%s", svc.Name, svc.Scheme, svc.RemoteAddr, svc.Scheme, svc.ExposedAddr)
	info, err := s.AddService(svc)
	if err != nil {
		log.Printf("Register Service [%s] Error: %v", svc.Name, err)
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}
	s.labelConn(c.Request, info.Name)
	c.IndentedJSON(http.StatusCreated, info)
}

func (s *Server) PutService(c *gin.Context) {
	name := c.Param("name")
	svc := &ServiceInfo{}
	if err := c.BindJSON(&svc); err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	svc.ExposedAddr = c.Request.RemoteAddr
	log.Printf("Update Service [%s]: %s://%s -> %s://%s", name, svc.Scheme, svc.RemoteAddr, svc.Scheme, svc.ExposedAddr)
	status := http.StatusOK
	s.mutex.Lock()
	info, err := s.updateService(c.Request.Context(), name, svc)
	if err == ErrorServiceNotFound {
		status = http.StatusCreated
		info, err = s.addService(svc)
	}
	s.mutex.Unlock()
	if err != nil {
		log.Printf("Update Service [%s] Error: %v", svc.Name, err)
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}
	s.labelConn(c.Request, info.Name)
	c.IndentedJSON(status, info)
}

func (s *Server) PutServiceExposedAddr(c *gin.Context) {
	name := c.Param("name")
	s.mutex.RLock()
	r, ok := s.reflectors[name]
	s.mutex.RUnlock()
	if !ok {
		c.IndentedJSON(http.StatusNotFound, gin.H{"message": "service not found"})
		return
	}
	info := r.GetServiceInfo()
	remoteAddr := c.Request.RemoteAddr
	if info.ExposedAddr != remoteAddr {
		r.UpdateAddr(&remoteAddr, nil)
		info.ExposedAddr = remoteAddr
		log.Printf("Update Service [%s]: %s://%s -> %s://%s", name, info.Scheme, info.RemoteAddr, info.Scheme, info.ExposedAddr)
	}
	s.labelConn(c.Request, info.Name)
	c.IndentedJSON(http.StatusOK, info)
}

func (s *Server) PutServiceProxyAddr(c *gin.Context) {
	name := c.Param("name")
	s.mutex.RLock()
	r, ok := s.reflectors[name]
	s.mutex.RUnlock()
	if !ok {
		c.IndentedJSON(http.StatusNotFound, gin.H{"message": "service not found"})
		return
	}
	info := r.GetServiceInfo()
	remoteAddr := c.Request.RemoteAddr
	if info.ProxyAddr != remoteAddr {
		info.ProxyAddr = remoteAddr
		log.Printf("Update Service [%s]: %s://%s -> %s://%s", name, info.Scheme, info.RemoteAddr, info.Scheme, info.ExposedAddr)
		r.UpdateAddr(nil, &remoteAddr)
	}
	s.labelConn(c.Request, info.Name)
	c.IndentedJSON(http.StatusOK, info)
}

func (s *Server) DeleteService(c *gin.Context) {
	name := c.Param("name")
	log.Printf("Delete Service [%s]", name)
	if err := s.DelService(c.Request.Context(), name); err != nil {
		log.Printf("Delete Service [%s] Error: %v", name, err)
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}
	c.IndentedJSON(http.StatusOK, gin.H{"message": "service deleted"})
}

type wrappedConn struct {
	net.Conn
	br      *bufio.Reader
	prepend []byte
	svc     *string // Tracking service corresponding to conn
}

func (c *wrappedConn) Read(b []byte) (int, error) {
	if len(c.prepend) > 0 {
		n := copy(b, c.prepend)
		if n == len(c.prepend) {
			c.prepend = nil
		} else {
			c.prepend = c.prepend[n:]
		}
		return n, nil
	}
	return c.br.Read(b)
}

func (s *Server) handle(conn net.Conn, fl *forwardListener, isTLS bool) {
	// track only conns under server's control
	s.trackConn(&conn, true)
	defer s.trackConn(&conn, false)
	br := bufio.NewReader(conn)

	var readahead []byte
	host := ""
	var err error
	if !isTLS {
		// We assume it is an HTTP request
		// HTTP sniff
		readahead, host, err = readHTTPHost(br)
	} else {
		// TLS sniff
		readahead, host, err = readClientHelloRecord(br)
	}
	if err != nil {
		log.Printf("[handle] %s -> %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
		conn.Close()
		return
	}
	conn = &wrappedConn{br: br, Conn: conn, prepend: readahead}

	if r, found := s.matchHost(host, isTLS); found {
		err = r.Handle(conn)
		if err != nil {
			log.Printf("[service] %s -> %s : %s",
				conn.RemoteAddr(), conn.LocalAddr(), err)
		}
		conn.Close()
	} else {
		fl.Forward(conn)
	}
}

func (s *Server) matchHost(host string, isTLS bool) (*ServiceReflector, bool) {
	if len(host) == 0 {
		return nil, false
	}
	var mux *map[string]*ServiceReflector
	if !isTLS {
		mux = &s.httpMux
	} else {
		mux = &s.httpsMux
	}
	// Match Exact hostname
	if r, ok := (*mux)[host]; ok {
		return r, true
	}
	// Match leading asterisk
	for key, reflector := range (*mux) {
		if !strings.HasPrefix(key, "*") {
			continue
		}
		if strings.HasSuffix(host, key[1:]) {
			return reflector, true
		}
	}
	// Match trailing asterisk
	for key, reflector := range (*mux) {
		if !strings.HasSuffix(key, "*") {
			continue
		}
		if strings.HasPrefix(host, key[:len(key)-1]) {
			return reflector, true
		}
	}
	return nil, false
}

func (s *Server) connState(conn net.Conn, state http.ConnState) {
	if state != http.StateClosed {
		return
	}
	if tc, ok := conn.(*tls.Conn); ok {
		conn = tc.NetConn()
	}
	wc, ok := conn.(*wrappedConn)
	if !ok || wc.svc == nil {
		return
	}
	name := *wc.svc
	log.Printf("Service [%s] conn closed, Deleting.", name)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := s.DelService(ctx, name); err != nil && err != ErrorServiceNotFound {
		log.Printf("Delete Service [%s] Error: %v", name, err)
	}
	cancel()
}

func (s *Server) serve(l net.Listener, isTLS bool) error {
	if s.shuttingDown() {
		return errors.New("cannot serve on closed server")
	}
	l = &onceCloseListener{Listener: l}
	defer func() {
		s.trackListener(&l, false)
		l.Close()
	}()
	s.trackListener(&l, true)

	fl := newForwardListener(l.Addr())
	if isTLS {
		go s.httpServer.ServeTLS(fl, "", "")
	} else {
		go s.httpServer.Serve(fl)
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			if s.shuttingDown() {
				return http.ErrServerClosed
			}
			return err
		}
		go s.handle(conn, fl, isTLS)
	}
}

func (s *Server) Serve(l net.Listener) error {
	return s.serve(l, false)
}

func (s *Server) ServeTLS(l net.Listener) error {
	return s.serve(l, true)
}

func (s *Server) Shutdown(ctx context.Context) error {
	close(s.shutdown)
	// Graceful Shutdown until context done
	waitCh := make(chan struct{})
	go func() {
		for ln := range s.listeners {
			(*ln).Close()
		}
		s.connGroup.Wait() // wait for conns
		s.listenerGroup.Wait()
		s.httpServer.Shutdown(ctx)
		close(waitCh)
	}()
	select {
	case <-ctx.Done():
		// Force close
		for c := range s.conns {
			(*c).Close()
		}
		return ctx.Err()
	case <-waitCh:
		return nil
	}
}

func (s *Server) shuttingDown() bool {
	select {
	case <-s.shutdown:
		return true
	default:
	}
	return false
}

func (s *Server) trackListener(ln *net.Listener, add bool) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if add {
		if s.shuttingDown() {
			return false
		}
		s.listeners[ln] = struct{}{}
		s.listenerGroup.Add(1)
	} else {
		delete(s.listeners, ln)
		s.listenerGroup.Done()
	}
	return true
}

func (s *Server) trackConn(conn *net.Conn, add bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if add {
		s.conns[conn] = struct{}{}
		s.connGroup.Add(1)
	} else {
		delete(s.conns, conn)
		s.connGroup.Done()
	}
}

type forwardListener struct {
	pipe chan net.Conn
	addr net.Addr
}

func newForwardListener(addr net.Addr) *forwardListener {
	return &forwardListener{
		pipe: make(chan net.Conn),
		addr: addr,
	}
}

func (l *forwardListener) Forward(conn net.Conn) {
	l.pipe <- conn
}

func (l *forwardListener) Accept() (net.Conn, error) {
	conn, ok := <-l.pipe
	if !ok {
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (l *forwardListener) Addr() net.Addr {
	return l.addr
}

func (l *forwardListener) Close() error {
	close(l.pipe)
	return nil
}

func readHTTPHost(r *bufio.Reader) ([]byte, string, error) {
	host := ""
	req, err := http.ReadRequest(r)
	if err != nil {
		return nil, "", err
	}
	// Prepend the read part
	buf := &bytes.Buffer{}
	if req.URL.IsAbs() {
		req.WriteProxy(buf)
	} else {
		req.Write(buf)
	}
	if h, _, err := net.SplitHostPort(req.Host); err == nil {
		host = h
	}
	return buf.Bytes(), host, nil
}

func readClientHelloRecord(r io.Reader) ([]byte, string, error) {
	host := ""
	record, err := dissector.ReadRecord(r)
	if err != nil {
		return nil, "", err
	}
	clientHello := &dissector.ClientHelloHandshake{}
	if err := clientHello.Decode(record.Opaque); err != nil {
		return nil, "", err
	}

	for _, ext := range clientHello.Extensions {
		if ext.Type() == dissector.ExtServerName {
			snExtension := ext.(*dissector.ServerNameExtension)
			host = snExtension.Name
			break
		}
	}
	record.Opaque, err = clientHello.Encode()
	if err != nil {
		return nil, "", err
	}

	buf := &bytes.Buffer{}
	if _, err := record.WriteTo(buf); err != nil {
		return nil, "", err
	}

	return buf.Bytes(), host, nil
}
