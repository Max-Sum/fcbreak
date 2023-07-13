package fcbreak

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

type HTTPService struct {
	info     ServiceInfo
	cfg      *ServiceConf
	serv     *http.Server
	revproxy *httputil.ReverseProxy
	proxy    *HTTPProxy
}

func NewHTTPService(name string, cfg *ServiceConf) *HTTPService {
	s := &HTTPService{
		info: ServiceInfo{
			Name:   name,
			Scheme: cfg.Scheme,
		},
		cfg: cfg,
	}
	if cfg.RemotePort > 0 {
		s.info.RemoteAddr = fmt.Sprintf("%s:%d", cfg.RemoteAddr, cfg.RemotePort)
	}
	s.serv = &http.Server{
		ConnContext: saveConnInContext,
		Handler:     s,
	}
	// HTTP Reverse Proxy
	u := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", cfg.LocalAddr, s.cfg.LocalPort),
	}
	if cfg.Backend == "https" {
		u.Scheme = "https"
	}
	s.revproxy = httputil.NewSingleHostReverseProxy(u)
	s.revproxy.ModifyResponse = s.ModifyResponse
	hosts := strings.Split(cfg.HTTPServiceConf.Hostname, ",")
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if len(host) == 0 {
			continue
		}
		if !verifyHostname(host) {
			log.Fatalf("host %s is illegal, host can contains no or one * at the beginning or at the ending", host)
		}
		s.info.Hostnames = append(s.info.Hostnames, strings.ToLower(host))
	}

	// HTTP Proxy protocol
	if s.cfg.Backend == "proxy" {
		s.proxy = NewHTTPProxy(s)
		s.serv.Handler = s.proxy
	}
	return s
}

func (s *HTTPService) GetCfg() *ServiceConf {
	return s.cfg
}

func (s *HTTPService) GetInfo() *ServiceInfo {
	return &s.info
}

func (s *HTTPService) SetExposedAddr(addr string) {
	s.info.ExposedAddr = addr
}

func (s *HTTPService) Serve(l net.Listener) (err error) {
	if s.info.Scheme == "http" {
		return s.serv.Serve(l)
	}
	return s.serv.ServeTLS(l, s.cfg.HTTPServiceConf.TLSCert, s.cfg.HTTPServiceConf.TLSKey)
}

// HTTP Reverse Proxy Handler
func (s *HTTPService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.auth(r, w)
	conn, ok := getConnUnwarpTLS(r).(svcInitConn)
	if !ok {
		log.Println("Conn is not svcInitConn.")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Proxied from Server
	useAltSvc := s.cfg.AltSvc && supportAltSvc(r.UserAgent())
	if conn.IsReflected && !useAltSvc {
		u := r.URL
		if r.TLS == nil {
			u.Scheme = "http"
		} else {
			u.Scheme = "https"
		}
		host, port, _ := s.ExposedDomainPort()
		u.Host = net.JoinHostPort(host, port)
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
	s.revproxy.ServeHTTP(w, r)
}

func (s *HTTPService) Shutdown(ctx context.Context) error {
	return s.serv.Shutdown(ctx)
}

func (s *HTTPService) auth(r *http.Request, w http.ResponseWriter) {
	if len(s.cfg.Username)+len(s.cfg.Password) > 0 {
		u, p, ok := r.BasicAuth()
		if !ok {
			log.Println("Error parsing basic auth")
			w.WriteHeader(401)
			return
		}
		if u != s.cfg.Username {
			fmt.Printf("Username provided is incorrect: %s\n", u)
			w.WriteHeader(401)
			return
		}
		if p != s.cfg.Password {
			fmt.Printf("Password provided is incorrect: %s\n", u)
			w.WriteHeader(401)
			return
		}
	}
}

func (s *HTTPService) ExposedDomainPort() (string, string, error) {
	host, port, err := net.SplitHostPort(s.info.ExposedAddr)
	if err != nil {
		return "", "", err
	}
	if len(s.cfg.NIPDomain) > 0 {
		host = strings.ReplaceAll(host, ".", "-") + "." + s.cfg.NIPDomain
	} else if len(s.cfg.DDNSDomain) > 0 {
		host = s.cfg.DDNSDomain
	}
	return host, port, nil
}

func (s *HTTPService) ModifyResponse(r *http.Response) error {
	conn, ok := getConnUnwarpTLS(r.Request).(svcInitConn)
	if !ok {
		return errors.New("conn is not SvcInitConn")
	}
	useAltSvc := s.cfg.AltSvc && supportAltSvc(r.Request.UserAgent())
	if !conn.IsReflected || !useAltSvc {
		return nil
	}
	host, port, err := s.ExposedDomainPort()
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(host, port)
	if u, ok := r.Request.Header["Alt-Used"]; ok && u[0] == addr {
		return nil
	}
	altsvc := fmt.Sprintf("h2=\"%s\"; ma=%d; persist=1", addr, s.cfg.CacheTime)
	r.Header.Add("Alt-Svc", altsvc)
	return nil
}
