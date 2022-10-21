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
	*Service
	serv     *http.Server
	revproxy *httputil.ReverseProxy
	proxy    *HTTPProxy
}

func (s *HTTPService) Serve(l net.Listener) (err error) {
	s.serv = &http.Server{
		ConnContext: SaveConnInContext,
		Handler:     s,
	}

	// HTTP Reverse Proxy
	if s.Cfg.Backend == "http" || s.Cfg.Backend == "https" {
		u := &url.URL{
			Scheme: "http",
			Host:   fmt.Sprintf("%s:%d", s.Cfg.LocalAddr, s.Cfg.LocalPort),
		}
		if s.Cfg.Backend == "https" {
			u.Scheme = "https"
		}
		s.revproxy = httputil.NewSingleHostReverseProxy(u)
		s.revproxy.ModifyResponse = s.ModifyResponse
	}

	// HTTP Proxy protocol
	if s.Cfg.Backend == "proxy" {
		s.proxy = NewHTTPProxy(s.Service)
		s.serv.Handler = s.proxy
	}

	if s.Scheme == "http" {
		return s.serv.Serve(l)
	}
	return s.serv.ServeTLS(l, s.Cfg.HTTPServiceConf.TLSCert, s.Cfg.HTTPServiceConf.TLSKey)
}

// HTTP Reverse Proxy Handler
func (s *HTTPService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.auth(r, w)
	conn, ok := GetConnUnwarpTLS(r).(SvcInitConn)
	if !ok {
		log.Println("Conn is not SvcInitConn.")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Proxied from Server
	useAltSvc := s.Cfg.AltSvc && SupportAltSvc(r.UserAgent())
	if conn.IsReflected && !useAltSvc {
		u := r.URL
		if r.TLS == nil {
			u.Scheme = "http"
		} else {
			u.Scheme = "https"
		}
		u.Host, _ = s.exposedAddr()
		// Redirect with Cache Control
		h := w.Header()
		_, hadCT := h["Content-Type"]
		h.Set("Cache-Control", fmt.Sprintf("max-age=%ds", int(s.Cfg.HTTPServiceConf.CacheTime)))
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

func (s *HTTPService) Shutdown() error {
	return s.serv.Shutdown(context.Background())
}

func (s *HTTPService) auth(r *http.Request, w http.ResponseWriter) {
	if len(s.Cfg.Username)+len(s.Cfg.Password) > 0 {
		u, p, ok := r.BasicAuth()
		if !ok {
			log.Println("Error parsing basic auth")
			w.WriteHeader(401)
			return
		}
		if u != s.Cfg.Username {
			fmt.Printf("Username provided is incorrect: %s\n", u)
			w.WriteHeader(401)
			return
		}
		if p != s.Cfg.Password {
			fmt.Printf("Password provided is incorrect: %s\n", u)
			w.WriteHeader(401)
			return
		}
	}
}

func (s *HTTPService) exposedAddr() (string, error) {
	host, port, err := net.SplitHostPort(s.ExposedAddr)
	if err != nil {
		return s.ExposedAddr, err
	}
	if len(s.Cfg.NIPDomain) > 0 {
		host = strings.ReplaceAll(host, ".", "-") + "." + s.Cfg.NIPDomain
	} else if len(s.Cfg.DDNSDomain) >0 {
		host = s.Cfg.DDNSDomain
	}
	return net.JoinHostPort(host, port), nil
}

func (s *HTTPService) ModifyResponse(r *http.Response) error {
	conn, ok := GetConnUnwarpTLS(r.Request).(SvcInitConn)
	if !ok {
		return errors.New("conn is not SvcInitConn")
	}
	useAltSvc := s.Cfg.AltSvc && SupportAltSvc(r.Request.UserAgent())
	if !conn.IsReflected || !useAltSvc {
		return nil
	}
	addr, err := s.exposedAddr()
	if err != nil {
		return err
	}
	if u, ok := r.Request.Header["Alt-Used"]; ok && u[0] == addr {
		return nil
	}
	altsvc := fmt.Sprintf("h2=\"%s\"; ma=%d; persist=1", addr, s.Cfg.CacheTime)
	r.Header.Add("Alt-Svc", altsvc)
	return nil
}
