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
	proxyproto "github.com/pires/go-proxyproto"
)

var (
	ErrorServiceNotFound = errors.New("Service is not found")
)

// ServiceInfo is a service wrapper
type TimedService struct {
	*ServiceReflector
	updateCh chan struct{}
	closeCh  chan struct{}
}

func (svc TimedService) Timeout(s *Server) {
	for {
		select {
		case <-time.After(30 * time.Minute):
			info := svc.GetServiceInfo()
			log.Printf("Service [%s] Timeout\n", info.Name)
			if err := s.DelService(info.Name); err != nil {
				log.Printf("Service [%s] Stop Error: %v\n", info.Name, err)
			}
			return
		case <-svc.updateCh:
			// Check if the service is ended.
			select {
			case _, ok := <-svc.closeCh:
				if !ok {
					return
				}
			default:
			}
		}
	}
}

// GetServiceInfoForOutput filters fields for output
func (svc TimedService) GetServiceInfoForOutput() ServiceInfo {
	info := svc.GetServiceInfo()
	info.ProxyAddr = ""
	return info
}

func (svc TimedService) Stop() error {
	close(svc.closeCh)
	return svc.ServiceReflector.Stop()
}

type Server struct {
	User       string
	Pass       string
	mutex      sync.RWMutex
	shutdown   chan struct{}
	reflectors map[string]TimedService
	httpMux    map[string]*ServiceReflector
	httpsMux   map[string]*ServiceReflector
}

func NewServer() *Server {
	return &Server{
		User:       "",
		Pass:       "",
		mutex:      sync.RWMutex{},
		shutdown:   make(chan struct{}),
		reflectors: map[string]TimedService{},
		httpMux:    map[string]*ServiceReflector{},
		httpsMux:   map[string]*ServiceReflector{},
	}
}

// not thread-safe!
func (s *Server) addService(svc *ServiceInfo) (*ServiceInfo, error) {
	if r, found := s.reflectors[svc.Name]; found {
		info := r.GetServiceInfo()
		return &info, errors.New("Service [" + svc.Name + "] already exists.")
	}
	r := NewServiceReflector(svc)
	if len(r.info.RemoteAddr) > 0 {
		if err := r.Listen(); err != nil {
			return nil, err
		}
		go r.Serve()
	}
	s.reflectors[svc.Name] = TimedService{
		ServiceReflector: r,
		updateCh:         make(chan struct{}),
		closeCh:          make(chan struct{}),
	}
	if svc.Scheme == "http" {
		for _, host := range svc.Hostnames {
			if len(host) > 0 {
				s.httpMux[host] = r
			}
		}
	} else if svc.Scheme == "https" {
		for _, host := range svc.Hostnames {
			if len(host) > 0 {
				s.httpsMux[host] = r
			}
		}
	}

	go s.reflectors[svc.Name].Timeout(s)
	return svc, nil
}

// not thread-safe!
func (s *Server) updateService(name string, svc *ServiceInfo) (*ServiceInfo, error) {
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
			if err := s.delService(oldInfo.Name); err != nil {
				return nil, err
			}
			return s.addService(svc)
		}
		// Update Address
		if oldInfo.ExposedAddr != svc.ExposedAddr || oldInfo.ProxyAddr != svc.ProxyAddr {
			log.Printf("Update Service Address: [%s]", svc.Name)
			oldSvc.UpdateAddr(&svc.ExposedAddr, &svc.ProxyAddr)
		}
		// Reset timer
		oldSvc.updateCh <- struct{}{}
		return &oldInfo, nil
	}
	return nil, ErrorServiceNotFound
}

// not thread-safe!
func (s *Server) delService(name string) error {
	if svc, found := s.reflectors[name]; found {
		svc.Stop()
		info := svc.GetServiceInfo()
		if info.Scheme == "http" {
			for _, host := range info.Hostnames {
				if len(host) > 0 {
					delete(s.httpMux, host)
				}
			}
		} else if info.Scheme == "https" {
			for _, host := range info.Hostnames {
				if len(host) > 0 {
					delete(s.httpMux, host)
				}
			}
		}
		delete(s.reflectors, name)
		return nil
	}
	return ErrorServiceNotFound
}

func (s *Server) AddService(svc *ServiceInfo) (*ServiceInfo, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.addService(svc)
}

func (s *Server) UpdateService(name string, svc *ServiceInfo) (*ServiceInfo, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.updateService(name, svc)
}

func (s *Server) DelService(name string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.delService(name)
}

func (s *Server) GetServices(c *gin.Context) {
	svcs := make(map[string]ServiceInfo)
	s.mutex.RLock()
	for n, r := range s.reflectors {
		svcs[n] = r.GetServiceInfoForOutput()
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
	c.IndentedJSON(http.StatusOK, r.GetServiceInfoForOutput())
}

func getRealAddr(req *http.Request) string {
	addr := req.RemoteAddr
	_, port, _ := net.SplitHostPort(addr)
	if fwaddr := req.Header.Get("X-Real-IP"); fwaddr != "" {
		return net.JoinHostPort(fwaddr, port)
	}
	if fwaddr := req.Header.Get("X-Forwarded-For"); fwaddr != "" {
		return net.JoinHostPort(strings.Split(fwaddr, ", ")[0], port)
	}
	return addr
}

func (s *Server) PostService(c *gin.Context) {
	svc := &ServiceInfo{}
	if err := c.BindJSON(&svc); err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	svc.ExposedAddr = getRealAddr(c.Request)
	log.Printf("Register Service [%s]: %s://%s -> %s://%s", svc.Name, svc.Scheme, svc.RemoteAddr, svc.Scheme, svc.ExposedAddr)
	info, err := s.AddService(svc)
	if err != nil {
		log.Printf("Register Service [%s] Error: %v", svc.Name, err)
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}

	c.IndentedJSON(http.StatusOK, info)
}

func (s *Server) PutService(c *gin.Context) {
	name := c.Param("name")
	svc := &ServiceInfo{}
	if err := c.BindJSON(&svc); err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	svc.ExposedAddr = getRealAddr(c.Request)
	log.Printf("Update Service [%s]: %s://%s -> %s://%s", name, svc.Scheme, svc.RemoteAddr, svc.Scheme, svc.ExposedAddr)
	s.mutex.Lock()
	info, err := s.updateService(name, svc)
	if err == ErrorServiceNotFound {
		info, err = s.addService(svc)
	}
	s.mutex.Unlock()
	if err != nil {
		log.Printf("Update Service [%s] Error: %v", svc.Name, err)
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}

	c.IndentedJSON(http.StatusOK, info)
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
	remoteAddr := getRealAddr(c.Request)
	if info.ExposedAddr != remoteAddr {
		r.UpdateAddr(&remoteAddr, nil)
		info.ExposedAddr = remoteAddr
		log.Printf("Update Service [%s]: %s://%s -> %s://%s", name, info.Scheme, info.RemoteAddr, info.Scheme, info.ExposedAddr)
	}
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
	remoteAddr := getRealAddr(c.Request)
	if info.ProxyAddr != remoteAddr {
		info.ProxyAddr = remoteAddr
		log.Printf("Update Service [%s]: %s://%s -> %s://%s", name, info.Scheme, info.RemoteAddr, info.Scheme, info.ExposedAddr)
		r.UpdateAddr(nil, &remoteAddr)
	}
	c.IndentedJSON(http.StatusOK, info)
}

func (s *Server) DeleteService(c *gin.Context) {
	name := c.Param("name")
	log.Printf("Delete Service [%s]", name)
	if err := s.DelService(name); err != nil {
		log.Printf("Delete Service [%s] Error: %v", name, err)
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}
	c.IndentedJSON(http.StatusOK, gin.H{"message": "service deleted"})
}

type bufferPrependConn struct {
	net.Conn
	br      *bufio.Reader
	prepend []byte
}

func (c *bufferPrependConn) Read(b []byte) (int, error) {
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
	br := bufio.NewReader(conn)

	var readahead []byte
	host := ""
	var err error
	if !isTLS {
		// We assume it is an HTTP request
		// HTTP sniff
		readahead, host, err = readHTTPHost(br)
		log.Printf("[handle] sniffing http: %s -> %s : host: %s",
			conn.RemoteAddr(), conn.LocalAddr(), host)
	} else {
		// TLS sniff
		readahead, host, err = readClientHelloRecord(br)
		log.Printf("[handle] sniffing https: %s -> %s : host: %s",
			conn.RemoteAddr(), conn.LocalAddr(), host)
	}
	if err != nil {
		log.Printf("[handle] %s -> %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}
	conn = &bufferPrependConn{br: br, Conn: conn, prepend: readahead}

	var r *ServiceReflector
	found := false
	if len(host) > 0 {
		if !isTLS {
			r, found = s.httpMux[host]
		} else {
			r, found = s.httpsMux[host]
		}
	}
	if found {
		err = r.Handle(conn)
		if err != nil {
			log.Printf("[service] %s -> %s : %s",
				conn.RemoteAddr(), conn.LocalAddr(), err)
		}
	} else {
		fl.Forward(conn)
	}
}

func (s *Server) ListenAndServe(addr string, tls *tls.Config, useProxyProto bool) error {
	select {
	case _, ok := <-s.shutdown:
		if !ok {
			return errors.New("cannot serve on closed server")
		}
	default:
	}

	router := gin.Default()
	serv := &http.Server{
		Addr:        addr,
		Handler:     router,
		IdleTimeout: 30 * time.Minute,
		TLSConfig:   tls,
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

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if useProxyProto {
		l = &proxyproto.Listener{Listener: l}
	}
	fl := newForwardListener(l.Addr())

	if tls == nil {
		go serv.Serve(fl)
	} else {
		go serv.ServeTLS(fl, "", "")
	}

	for {
		select {
		case <-s.shutdown:
			l.Close()
			return serv.Shutdown(context.Background())
		default:
		}
		log.Println("Accepting")
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			s.handle(conn, fl, tls != nil)
		}()
	}
}

func (s *Server) Shutdown() {
	close(s.shutdown)
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
