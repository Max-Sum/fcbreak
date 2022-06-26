package fcbreak

import (
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
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
func (s *Server) addService(svc *ServiceInfo) error {
	if _, found := s.reflectors[svc.Name]; found {
		return errors.New("Service [" + svc.Name + "] already exists.")
	}
	r := &ServiceReflector{
		ServiceInfo: svc,
		mutex:       sync.RWMutex{},
	}
	if err := r.Listen(); err != nil {
		return err
	}
	go r.Serve()
	s.reflectors[r.Name] = TimedService{
		ServiceReflector: r,
		updateCh:         make(chan struct{}),
	}

	go s.reflectors[svc.Name].Timeout(s)
	return nil
}

// not thread-safe!
func (s *Server) updateService(name string, svc *ServiceInfo) error {
	if oldSvc, found := s.reflectors[name]; found {
		if name != svc.Name {
			log.Printf("Rename Service: [%s] -> [%s]", name, svc.Name)
			oldSvc.Name = svc.Name
			delete(s.reflectors, name)
			s.reflectors[svc.Name] = oldSvc
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
	if svc, found := s.reflectors[name]; found {
		svc.Stop()
		svc.updateCh <- struct{}{} // Stop timer
		delete(s.reflectors, name)
		return nil
	}
	return ErrorServiceNotFound
}

func (s *Server) AddService(svc *ServiceInfo) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.addService(svc)
}

func (s *Server) UpdateService(name string, svc *ServiceInfo) error {
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
	svcs := make(map[string]*ServiceInfo)
	for n, r := range s.reflectors {
		svcs[n] = r.ServiceInfo
	}
	c.IndentedJSON(http.StatusOK, svcs)
}

func (s *Server) GetServiceByName(c *gin.Context) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	name := c.Param("name")
	if r, ok := s.reflectors[name]; ok {
		c.IndentedJSON(http.StatusOK, r.ServiceInfo)
		return
	}

	c.IndentedJSON(http.StatusNotFound, gin.H{"message": "service not found"})
}

func (s *Server) PostService(c *gin.Context) {
	svc := &ServiceInfo{}
	if err := c.BindJSON(&svc); err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	svc.ExposedAddr = c.Request.RemoteAddr
	log.Printf("Register Service [%s]: %s://%s -> %s://%s", svc.Name, svc.Scheme, svc.RemoteAddr, svc.Scheme, svc.ExposedAddr)
	if err := s.AddService(svc); err != nil {
		log.Printf("Register Service [%s] Error: %v", svc.Name, err)
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}

	c.IndentedJSON(http.StatusOK, svc)
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
	defer s.mutex.Unlock()
	err := s.updateService(name, svc)
	if err == ErrorServiceNotFound {
		err = s.addService(svc)
	}
	if err != nil {
		log.Printf("Update Service [%s] Error: %v", svc.Name, err)
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}

	c.IndentedJSON(http.StatusOK, svc)
}

func (s *Server) PutServiceProxyAddr(c *gin.Context) {
	name := c.Param("name")
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if r, ok := s.reflectors[name]; ok {
		r.ProxyAddr = c.Request.RemoteAddr
		c.IndentedJSON(http.StatusOK, r.ServiceInfo)
		log.Printf("Update Service [%s]: %s://%s -> %s://%s", name, r.Scheme, r.RemoteAddr, r.Scheme, r.ExposedAddr)
		return
	}
	c.IndentedJSON(http.StatusNotFound, gin.H{"message": "service not found"})
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
	r.PUT("/services/:name/proxy_addr", s.PutServiceProxyAddr)
	r.DELETE("/services/:name", s.DeleteService)

	serv.ListenAndServe()
}
