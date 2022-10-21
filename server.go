package fcbreak

import (
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/tools/go/analysis/passes/nilfunc"
)

var (
	ErrorServiceNotFound = errors.New("Service is not found")
)

// ServiceInfo is a service wrapper
type TimedService struct {
	*ServiceReflector
	updateCh chan (struct{})
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
			if !svc.Running() {
				return
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

type Server struct {
	User       string
	Pass       string
	mutex      sync.RWMutex
	reflectors map[string]TimedService
}

func NewServer() *Server {
	return &Server{
		User:       "",
		Pass:       "",
		mutex:      sync.RWMutex{},
		reflectors: map[string]TimedService{},
	}
}

// not thread-safe!
func (s *Server) addService(svc *ServiceInfo) (*ServiceInfo, error) {
	if r, found := s.reflectors[svc.Name]; found {
		info := r.GetServiceInfo()
		return &info, errors.New("Service [" + svc.Name + "] already exists.")
	}
	r := NewServiceReflector(svc)
	if err := r.Listen(); err != nil {
		return nil, err
	}
	go r.Serve()
	s.reflectors[svc.Name] = TimedService{
		ServiceReflector: r,
		updateCh:         make(chan struct{}),
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
		if oldInfo.RemoteAddr != svc.RemoteAddr || oldInfo.Scheme != svc.Scheme {
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

	c.IndentedJSON(http.StatusOK, info)
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
	if info.ExposedAddr != c.Request.RemoteAddr {
		r.UpdateAddr(&c.Request.RemoteAddr, nil)
		info.ExposedAddr = c.Request.RemoteAddr
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
	if info.ProxyAddr != c.Request.RemoteAddr {
		info.ProxyAddr = c.Request.RemoteAddr
		log.Printf("Update Service [%s]: %s://%s -> %s://%s", name, info.Scheme, info.RemoteAddr, info.Scheme, info.ExposedAddr)
		r.UpdateAddr(nil, &c.Request.RemoteAddr)
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

func (s *Server) ListenAndServe(addr string) {
	router := gin.Default()
	serv := &http.Server{
		Addr:        addr,
		Handler:     router,
		IdleTimeout: 30 * time.Minute,
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

	serv.ListenAndServe()
}
