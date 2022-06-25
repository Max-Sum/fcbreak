package fcbreak

import (
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pires/go-proxyproto"
)

var (
	ErrorServiceNotFound = errors.New("Service is not found")
)

type Service struct {
	l           net.Listener
	mutex       sync.RWMutex
	Name        string `json:"name" binding:"required"`
	RemoteAddr  string `json:"remote_addr" binding:"required"`
	ExposedAddr string `json:"exposed_addr,omitifempty"`
	Scheme      string `json:"scheme" binding:"required"`
}

func DefaultService() *Service {
	return &Service{
		l:           nil,
		mutex:       sync.RWMutex{},
		Name:        "",
		RemoteAddr:  "",
		ExposedAddr: "",
		Scheme:      "",
	}
}

// Handle an client request
func (s *Service) Handle(conn net.Conn) error {
	defer conn.Close()
	s.mutex.RLock()
	target, err := net.ResolveTCPAddr("tcp", s.ExposedAddr)
	if err != nil {
		return err
	}
	s.mutex.RUnlock()
	rconn, err := net.DialTCP("tcp", nil, target)
	if err != nil {
		return err
	}
	defer rconn.Close()
	// Write Proxy Scheme Header
	header := proxyproto.HeaderProxyFromAddrs(2, rconn.RemoteAddr(), target)
	_, err = header.WriteTo(rconn)
	if err != nil {
		return err
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

func (s *Service) Listen() error {
	if s.l != nil {
		return nil
	}
	l, err := net.Listen("tcp", s.RemoteAddr)
	if err != nil {
		log.Printf("Listen Error: %v", err)
		return err
	}
	s.l = l
	log.Printf("Service [%s] Listen: %s://%s\n", s.Name, s.Scheme, s.RemoteAddr)
	return nil
}

func (s *Service) Serve() {
	if s.l == nil {
		return
	}
	for {
		conn, err := s.l.Accept()
		if err != nil {
			log.Println("listener.Accept error:", err)
			break
		}
		go s.Handle(conn)
	}
	// Clear running bit
	if s.l != nil {
		s.l = nil
	}
	return
}
func (s *Service) Stop() error {
	if s.Running() {
		if err := s.l.Close(); err != nil {
			return err
		}
		s.l = nil
	}
	return nil
}

func (s *Service) Running() bool {
	return s.l != nil
}

// ServiceInfo is a service wrapper
type ServiceInfo struct {
	*Service
	updateCh chan (struct{})
}

func (svc ServiceInfo) Timeout(s *Server) {
	for {
		select {
		case <-time.After(30 * time.Minute):
			log.Printf("Service [%s] Timeout\n", svc.Name)
			if err := s.DelService(svc.Name); err != nil {
				log.Printf("Service [%s] Stop Error: %v\n", svc.Name, err)
			}
		case <-svc.updateCh:
			// Check if the service is ended.
			if !svc.Running() {
				return
			}
		}
	}
}

type Server struct {
	services map[string]ServiceInfo
	mutex    sync.RWMutex
}

func NewServer() *Server {
	return &Server{
		services: map[string]ServiceInfo{},
		mutex:    sync.RWMutex{},
	}
}

// not thread-safe!
func (s *Server) addService(svc *Service) error {
	if _, found := s.services[svc.Name]; found {
		return errors.New("Service [" + svc.Name + "] already exists.")
	}
	if err := svc.Listen(); err != nil {
		return err
	}
	go svc.Serve()
	s.services[svc.Name] = ServiceInfo{
		Service:  svc,
		updateCh: make(chan struct{}),
	}

	go s.services[svc.Name].Timeout(s)
	return nil
}

// not thread-safe!
func (s *Server) updateService(name string, svc *Service) error {
	if oldSvc, found := s.services[name]; found {
		if name != svc.Name {
			log.Printf("Rename Service: [%s] -> [%s]", name, svc.Name)
			oldSvc.Name = svc.Name
			delete(s.services, name)
			s.services[svc.Name] = oldSvc
		}
		// Need to restart
		if oldSvc.ExposedAddr != svc.ExposedAddr || oldSvc.RemoteAddr != svc.RemoteAddr || oldSvc.Scheme != svc.Scheme {
			log.Printf("Update Service: [%s] -> [%s]", name, svc.Name)
			if err := s.delService(oldSvc.Name); err != nil {
				return err
			}
			return s.addService(svc)
		}
		// Reset timer
		oldSvc.updateCh <- struct{}{}
		return nil
	}
	return ErrorServiceNotFound
}

// not thread-safe!
func (s *Server) delService(name string) error {
	if svc, found := s.services[name]; found {
		svc.Stop()
		svc.updateCh <- struct{}{} // Stop timer
		delete(s.services, name)
		return nil
	}
	return ErrorServiceNotFound
}

func (s *Server) AddService(svc *Service) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.addService(svc)
}

func (s *Server) UpdateService(name string, svc *Service) error {
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
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	c.JSON(http.StatusOK, s.services)
}

func (s *Server) GetServiceByName(c *gin.Context) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	name := c.Param("name")
	if service, ok := s.services[name]; ok {
		c.JSON(http.StatusOK, service)
		return
	}

	c.JSON(http.StatusNotFound, gin.H{"message": "service not found"})
}

func (s *Server) PostService(c *gin.Context) {
	svc := DefaultService()
	if err := c.BindJSON(&svc); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	svc.ExposedAddr = c.Request.RemoteAddr
	log.Printf("Register Service [%s]: %s://%s -> %s://%s", svc.Name, svc.Scheme, svc.RemoteAddr, svc.Scheme, svc.ExposedAddr)
	if err := s.AddService(svc); err != nil {
		log.Printf("Register Service [%s] Error: %v", svc.Name, err)
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, svc)
}

func (s *Server) PutService(c *gin.Context) {
	name := c.Param("name")
	svc := DefaultService()
	if err := c.BindJSON(&svc); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	svc.ExposedAddr = c.Request.RemoteAddr
	log.Printf("Update Service [%s]: %s://%s -> %s://%s", name, svc.Scheme, svc.RemoteAddr, svc.Scheme, svc.ExposedAddr)
	s.mutex.Lock()
	defer s.mutex.Unlock()
	err := s.updateService(name, svc)
	if err == ErrorServiceNotFound {
		err = s.addService(svc)
	}
	if err != nil {
		log.Printf("Update Service [%s] Error: %v", svc.Name, err)
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, svc)
}

func (s *Server) DeleteService(c *gin.Context) {
	name := c.Param("name")
	log.Printf("Delete Service [%s]", name)
	if err := s.DelService(name); err != nil {
		log.Printf("Delete Service [%s] Error: %v", name, err)
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "service deleted"})
}

func (s *Server) ListenAndServe(addr string) {
	router := gin.Default()
	serv := &http.Server{
		Addr:        addr,
		Handler:     router,
		IdleTimeout: 30 * time.Minute,
	}

	router.GET("/services", s.GetServices)
	router.GET("/services/:name", s.GetServiceByName)
	router.POST("/services", s.PostService)
	router.PUT("/services/:name", s.PutService)
	router.DELETE("/services/:name", s.DeleteService)

	serv.ListenAndServe()
}
