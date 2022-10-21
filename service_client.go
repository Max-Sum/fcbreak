package fcbreak

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	reuse "github.com/libp2p/go-reuseport"
	"github.com/pires/go-proxyproto"
)

type Service struct {
	ServiceInfo
	Cfg      ServiceConf
	httpServ *HTTPService
	l        net.Listener
	quitting chan struct{}
}

func NewService(name string, cfg ServiceConf) *Service {
	s := &Service{
		ServiceInfo: ServiceInfo{
			Name:       name,
			Scheme:     strings.ToLower(cfg.Scheme),
		},
		Cfg:      cfg,
		l:        nil,
		httpServ: nil,
		quitting: make(chan struct{}, 1),
	}
	if cfg.RemotePort > 0 {
		s.RemoteAddr = fmt.Sprintf("%s:%d", cfg.RemoteAddr, cfg.RemotePort)
	}
	if s.Scheme == "http" || s.Scheme == "https" {
		hosts := strings.Split(cfg.HTTPServiceConf.Hostname, ",")
		for _, host := range hosts {
			host = strings.TrimSpace(host)
			if len(host) == 0 { continue }
			s.ServiceInfo.Hostnames = append(s.ServiceInfo.Hostnames, strings.ToLower(host))
		}
	}
	return s
}

// Listen on both port
type svcInitMuxListener struct {
	net.Listener                      // Listener to direct access
	pListener    *proxyproto.Listener // Listener to server-forwarded access
	connCh       chan SvcInitMuxListenChanPair
	closed       bool
}

type SvcInitConn struct {
	net.Conn
	IsReflected bool // Indicates if the connection is via server
}

type SvcInitMuxListenChanPair struct {
	Conn *SvcInitConn
	Err  error
}

func newSvcInitMuxListener(dListener net.Listener, pListener *proxyproto.Listener) *svcInitMuxListener {
	l := &svcInitMuxListener{
		Listener:  dListener,
		pListener: pListener,
		connCh:    nil,
		closed:    true,
	}
	l.Start()
	return l
}

func (l *svcInitMuxListener) Start() {
	if l.Listening() {
		return
	}
	l.closed = false
	l.connCh = make(chan SvcInitMuxListenChanPair)
	if l.pListener != nil {
		go func() {
			for {
				c, e := l.pListener.Accept()
				if l.closed {
					return
				}
				var conn *SvcInitConn = nil
				if c != nil {
					conn = &SvcInitConn{c, true}
				}
				l.connCh <- SvcInitMuxListenChanPair{conn, e}
			}
		}()
	}
	go func() {
		for {
			c, e := l.Listener.Accept()
			if l.closed {
				return
			}
			var conn *SvcInitConn = nil
			if c != nil {
				conn = &SvcInitConn{c, false}
			}
			l.connCh <- SvcInitMuxListenChanPair{conn, e}
		}
	}()
}

// Accept on both Listener.
func (l *svcInitMuxListener) Accept() (net.Conn, error) {
	if ret, ok := <-l.connCh; ok {
		if ret.Conn != nil && ret.Conn.Conn != nil {
			return *ret.Conn, ret.Err
		}
		return nil, ret.Err
	}
	return nil, io.EOF
}

func (l *svcInitMuxListener) Close() error {
	l.closed = true
	err := l.Listener.Close()
	if l.pListener != nil {
		perr := l.pListener.Close()
		if err == nil {
			err = perr
		}
	}
	log.Printf("Close Listener: %s\n", l.Addr())
	close(l.connCh)
	l.connCh = nil
	return err
}

func (l *svcInitMuxListener) Addr() net.Addr {
	return l.Listener.Addr()
}

func (l *svcInitMuxListener) Listening() bool {
	return !l.closed
}

func (s *Service) Listen() (net.Listener, error) {
	dl, err := reuse.Listen("tcp", fmt.Sprintf("%s:%d", s.Cfg.BindAddr, s.Cfg.BindPort))
	if err != nil {
		log.Fatal("Listen: ", err)
		return nil, err
	}
	// Only do a proxy protocol port on proxy-aware protocols
	var pl *proxyproto.Listener = nil
	if s.Scheme == "http" || s.Scheme == "https" {
		l, err := reuse.Listen("tcp", fmt.Sprintf("%s:0", s.Cfg.BindAddr))
		if err != nil {
			dl.Close()
			log.Fatal("Listen: ", err)
			return nil, err
		}
		pl = &proxyproto.Listener{Listener: l}
	}
	l := newSvcInitMuxListener(dl, pl)
	log.Printf("Service [%s] Listen: %s://%s", s.Name, s.Scheme, dl.Addr().String())
	return l, nil
}

func (s *Service) Serve(l net.Listener) (err error) {
	// Proxy HTTP
	if s.Scheme == "http" || s.Scheme == "https" {
		s.httpServ = &HTTPService{Service: s}
		return s.httpServ.Serve(l)
	}
	// Proxy TCP
	s.l = l
	var conn net.Conn
	for {
		conn, err = l.Accept()
		if err != nil {
			select {
			case <-s.quitting:
				err = nil
			default:
				log.Println("listener.Accept error:", err)
			}
			break
		}
		go s.Handle(conn)
	}
	return err
}

func (s *Service) ListenAndServe() error {
	l, err := s.Listen()
	if err != nil {
		return err
	}
	return s.Serve(l)
}

func (s *Service) Shutdown() error {
	if s.httpServ != nil {
		err := s.httpServ.Shutdown()
		s.httpServ = nil
		return err
	}
	s.quitting <- struct{}{}
	return s.l.Close()
}

// Handle raw connection
func (s *Service) Handle(conn net.Conn) error {
	defer conn.Close()
	localAddr := fmt.Sprintf("%s:%d", s.Cfg.LocalAddr, s.Cfg.LocalPort)
	rconn, err := net.Dial("tcp", localAddr)
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
