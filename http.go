package fcbreak

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

type HTTPService struct {
	reqserv  *ReqService
	revproxy *httputil.ReverseProxy
	proxy    *HTTPProxy
}

func (s *HTTPService) Serve(l net.Listener) (err error) {
	serv := &http.Server{
		ConnContext: SaveConnInContext,
		Handler:     s,
	}

	// HTTP Reverse Proxy
	if s.reqserv.cfg.Backend == "http" || s.reqserv.cfg.Backend == "https" {
		u := &url.URL{
			Scheme: "http",
			Host:   fmt.Sprintf("%s:%d", s.reqserv.cfg.LocalAddr, s.reqserv.cfg.LocalPort),
		}
		if s.reqserv.cfg.Backend == "https" {
			u.Scheme = "https"
		}
		s.revproxy = httputil.NewSingleHostReverseProxy(u)
		s.revproxy.ModifyResponse = s.ModifyResponse
	}

	// HTTP Proxy protocol
	if s.reqserv.cfg.Backend == "proxy" {
		s.proxy = &HTTPProxy{s: s.reqserv}
		serv.Handler = s.proxy
	}

	if s.reqserv.Scheme == "http" {
		return serv.Serve(l)
	}
	return serv.ServeTLS(l, s.reqserv.cfg.HTTPServiceConf.TLSCert, s.reqserv.cfg.HTTPServiceConf.TLSKey)
}

// HTTP Reverse Proxy Handler
func (s *HTTPService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.auth(r, w)
	u := r.URL
	if r.TLS == nil {
		u.Scheme = "http"
	} else {
		u.Scheme = "https"
	}
	// Proxied from Server
	u.Host, _ = s.exposedAddr()
	if s.proxiedFromServer(r) && (!s.reqserv.cfg.AltSvc || !SupportAltSvc(r.UserAgent())) {
		// Redirect with Cache Control
		h := w.Header()
		_, hadCT := h["Content-Type"]
		h.Set("Cache-Control", fmt.Sprintf("max-age=%ds", int(s.reqserv.cfg.HTTPServiceConf.CacheTime)))
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

func (s *HTTPService) auth(r *http.Request, w http.ResponseWriter) {
	if len(s.reqserv.cfg.Username)+len(s.reqserv.cfg.Password) > 0 {
		u, p, ok := r.BasicAuth()
		if !ok {
			log.Println("Error parsing basic auth")
			w.WriteHeader(401)
			return
		}
		if u != s.reqserv.cfg.Username {
			fmt.Printf("Username provided is incorrect: %s\n", u)
			w.WriteHeader(401)
			return
		}
		if p != s.reqserv.cfg.Password {
			fmt.Printf("Password provided is incorrect: %s\n", u)
			w.WriteHeader(401)
			return
		}
	}
}

func (s *HTTPService) proxiedFromServer(r *http.Request) bool {
	serverIP, err := net.ResolveIPAddr("ip", s.reqserv.clientCfg.ServerAddr)
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

func (s *HTTPService) exposedAddr() (string, error) {
	if len(s.reqserv.cfg.NIPDomain) == 0 {
		return s.reqserv.ExposedAddr, nil
	}
	host, port, err := net.SplitHostPort(s.reqserv.ExposedAddr)
	if err != nil {
		return s.reqserv.ExposedAddr, err
	}
	host = strings.ReplaceAll(host, ".", "-") + "." + s.reqserv.cfg.NIPDomain
	return host + ":" + port, nil
}

func (s *HTTPService) ModifyResponse(r *http.Response) error {
	if !s.reqserv.cfg.AltSvc || !SupportAltSvc(r.Request.UserAgent()) {
		return nil
	}
	addr, err := s.exposedAddr()
	if err != nil {
		return err
	}
	if u, ok := r.Request.Header["Alt-Used"]; ok && u[0] == addr {
		return nil
	}
	altsvc := fmt.Sprintf("h2=\"%s\"; ma=%d; persist=1", addr, s.reqserv.cfg.CacheTime)
	r.Header.Add("Alt-Svc", altsvc)
	return nil
}
