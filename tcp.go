package fcbreak

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
)

type TCPService struct {
	info          ServiceInfo
	cfg           *ServiceConf
	shutdown      chan struct{}
	wg            sync.WaitGroup
	mu            sync.Mutex
	conns         map[*net.Conn]struct{}
	listeners     map[*net.Listener]struct{}
	listenerGroup sync.WaitGroup
}

func NewTCPService(name string, cfg *ServiceConf) *TCPService {
	s := &TCPService{
		info: ServiceInfo{
			Name:   name,
			Scheme: cfg.Scheme,
		},
		cfg:       cfg,
		shutdown:  make(chan struct{}),
		conns:     make(map[*net.Conn]struct{}),
		listeners: make(map[*net.Listener]struct{}),
	}
	if cfg.RemotePort > 0 {
		s.info.RemoteAddr = fmt.Sprintf("%s:%d", cfg.RemoteAddr, cfg.RemotePort)
	}
	return s
}

func (s *TCPService) GetCfg() *ServiceConf {
	return s.cfg
}

func (s *TCPService) GetInfo() *ServiceInfo {
	return &s.info
}

func (s *TCPService) Serve(l net.Listener) (err error) {
	if s.shuttingDown() {
		return errors.New("cannot serve on closed server")
	}
	l = &onceCloseListener{Listener: l}
	defer func() {
		s.trackListener(&l, false)
		l.Close()
	}()
	s.trackListener(&l, true)
	var conn net.Conn
	for {
		conn, err = l.Accept()
		if err != nil {
			if err == net.ErrClosed {
				return nil
			}
			if s.shuttingDown() {
				return http.ErrServerClosed
			}
			log.Printf("[%s] listener.Accept error: %v", s.cfg.Name, err)
			break
		}
		go func() {
			if err := s.Handle(conn); err != nil {
				log.Printf("[%s] handle conn error: %v", s.cfg.Name, err)
			}
		}()
	}
	return err
}

func (s *TCPService) Shutdown(ctx context.Context) error {
	close(s.shutdown)
	// Graceful Shutdown until context done
	waitCh := make(chan struct{})
	go func() {
		for ln := range s.listeners {
			(*ln).Close()
		}
		s.wg.Wait()
		s.listenerGroup.Wait()
		close(waitCh)
	}()
	select {
	case <-ctx.Done():
		for c := range s.conns {
			(*c).Close()
		}
		return ctx.Err()
	case <-waitCh:
		return nil
	}
}

// Handle raw connection
func (s *TCPService) Handle(conn net.Conn) error {
	s.trackConn(&conn, true)
	defer func() {
		s.trackConn(&conn, false)
		conn.Close()
	}()
	localAddr := fmt.Sprintf("%s:%d", s.cfg.LocalAddr, s.cfg.LocalPort)
	rconn, err := net.Dial("tcp", localAddr)
	if err != nil {
		return err
	}
	defer rconn.Close()
	return transport(conn, rconn)
}

func (s *TCPService) trackListener(ln *net.Listener, add bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
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

func (s *TCPService) shuttingDown() bool {
	select {
	case <-s.shutdown:
		return true
	default:
	}
	return false
}

func (s *TCPService) trackConn(conn *net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
	} else {
		delete(s.conns, conn)
		s.wg.Done()
	}
}
