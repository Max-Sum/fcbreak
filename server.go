package fcbreak

import (
	"encoding/gob"
	"errors"
	"io"
	"log"
	"net"
	"sync"

	"github.com/pires/go-proxyproto"
)

type Service struct {
	l           net.Listener
	mutex       sync.RWMutex
	Name        string
	RemoteAddr  string
	ExposedAddr string
	Scheme      string
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
	// Write Proxy Protocol Header
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

// ListenAndServe on s.RemoteAddr
func (s *Service) ListenAndServe() error {
	s.mutex.Lock()
	l, err := net.Listen("tcp", s.RemoteAddr)
	if err != nil {
		log.Fatalf("%v", err)
		return err
	}
	s.l = l
	s.mutex.Unlock()
	log.Printf("Service Listen: %s://%s", s.Scheme, s.RemoteAddr)
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println("listener.Accept error:", err)
			break
		}
		go s.Handle(conn)
	}
	return err
}

func (s *Service) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.l != nil {
		if err := s.l.Close(); err != nil {
			return err
		}
		s.l = nil
	}
	return nil
}

type Server struct {
	services map[string]*Service
}

func NewServer() *Server {
	return &Server{
		services: map[string]*Service{},
	}
}

const (
	PACKET_TYPE_PING     = 0
	PACKET_TYPE_PONG     = 1
	PACKET_TYPE_REGISTER = 2
	PACKET_TYPE_REFLECT  = 3
)

type Packet struct {
	PacketType  byte
	ServiceInfo *Service
}

func (s *Server) Handle(conn net.Conn) {
	defer conn.Close()
	dec := gob.NewDecoder(conn)
	enc := gob.NewEncoder(conn)
	p := &Packet{}
	var name string
	for {
		err := dec.Decode(p)
		if err != nil {
			if err != io.EOF {
				log.Printf("Decode error: %v\n", err)
			}
			break
		}
		switch p.PacketType {
		case PACKET_TYPE_PING:
			p.PacketType = PACKET_TYPE_PONG
			err = enc.Encode(p)
		case PACKET_TYPE_PONG:
			continue
		case PACKET_TYPE_REGISTER:
			err = s.handleRegister(conn, p)
			name = p.ServiceInfo.Name
		default:
			err = errors.New("unsupported packet type")
		}
		if err != nil {
			log.Printf("Error: %v\n", err)
			break
		}
	}
	if len(name) > 0 {
		if svc, found := s.services[name]; found {
			svc.Close()
			delete(s.services, name)
		}
	}
}

func (s *Server) handleRegister(conn net.Conn, p *Packet) error {
	enc := gob.NewEncoder(conn)
	p.ServiceInfo.ExposedAddr = conn.RemoteAddr().String()
	info := p.ServiceInfo
	log.Printf("New Service [%s]: %s://%s -> %s://%s", info.Name, info.Scheme, info.RemoteAddr, info.Scheme, info.ExposedAddr)
	// Start Service
	if _, found := s.services[info.Name]; found {
		return errors.New("service with same name " + info.Name + " exists")
	}
	svc := &Service{
		l:           nil,
		mutex:       sync.RWMutex{},
		Name:        info.Name,
		RemoteAddr:  info.RemoteAddr,
		ExposedAddr: info.ExposedAddr,
		Scheme:      info.Scheme,
	}
	s.services[info.Name] = svc
	if len(svc.RemoteAddr) > 0 && svc.l == nil {
		go svc.ListenAndServe()
	}
	p.PacketType = PACKET_TYPE_REFLECT
	enc.Encode(p)
	return nil
}

func (s *Server) ListenAndServe(addr string) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		log.Fatalf("net.ResovleTCPAddr fail:%s", addr)
	}
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		log.Fatalf("listen %s fail: %s", addr, err)
	} else {
		log.Println("rpc listening: ", addr)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("listener.Accept error:", err)
			continue
		}
		go s.Handle(conn)

	}
}
