package fcbreak

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/proxy"
)

type HTTPProxy struct {
	s      *HTTPService
	tp     http.Transport
	dialer proxy.Dialer
}

func NewHTTPProxy(s *HTTPService) *HTTPProxy {
	p := &HTTPProxy{
		s:      s,
		tp:     http.Transport{},
		dialer: proxy.Direct,
	}
	// proxy
	if s.GetCfg().ChainProxy != "" {
		httpProxyURI, err := url.Parse(s.GetCfg().ChainProxy)
		if err != nil {
			log.Fatalf("%v", err)
		}
		p.dialer, err = proxy.FromURL(httpProxyURI, proxy.Direct)
		if err != nil {
			log.Fatalf("%v", err)
		}
		p.tp.Dial = p.dialer.Dial
	}
	return p
}

func (hp *HTTPProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Info
	if req.Method != http.MethodConnect && !req.URL.IsAbs() {
		if ok := hp.Auth(req, "Authorization"); !ok {
			rw.Header().Set("WWW-Authenticate", `Basic realm="Restricted API", charset="UTF-8"`)
			http.Error(rw, "Unauthorized", http.StatusUnauthorized)
			return
		}
		hp.InfoHandler(rw, req)
		return
	}
	// Proxy
	if ok := hp.Auth(req, "Proxy-Authorization"); !ok {
		rw.Header().Set("Proxy-Authenticate", "Basic")
		rw.WriteHeader(http.StatusProxyAuthRequired)
		return
	}

	if req.Method == http.MethodConnect {
		hp.ConnectHandler(rw, req)
	} else {
		hp.HTTPHandler(rw, req)
	}
}

func (hp *HTTPProxy) InfoHandler(rw http.ResponseWriter, req *http.Request) {
	info := hp.s.GetInfo()
	cfg := hp.s.GetCfg()
	clashTemp := `proxies:
  - {name: %[1]s, type: http, server: %[3]s, port: %[4]s, tls: %[7]t, sni: %[2]s, username: %[8]s, password: %[9]s, skip-cert-verify: %[10]t}
  - {name: %[1]s (via Server), type: http, server: %[5]s, port: %[6]s, tls: %[7]t, sni: %[2]s, username: %[8]s, password: %[9]s, skip-cert-verify: %[10]t}`
	quanxTemp := `http=%[3]s:%[4]s, username=%[8]s, password=%[9]s, over-tls=%[7]t, tls-host=%[2]s, tls-verification=%[10]t, fast-open=false, udp-relay=false, tag=%[1]s
http=%[5]s:%[6]s, username=%[8]s, password=%[9]s, over-tls=%[7]t, tls-host=%[2]s, tls-verification=%[10]t, fast-open=false, udp-relay=false, tag=%[1]s (via Server)`
	name := info.Name
	scheme := info.Scheme
	eip, eportStr, err := net.SplitHostPort(info.ExposedAddr)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	if !req.URL.IsAbs() {
		req.URL.Host = req.Host
	}
	tls := scheme == "https"
	rip := req.URL.Hostname()
	rportStr := req.URL.Port()
	if rportStr == "" {
		if tls {
			rportStr = "443"
		} else {
			rportStr = "80"
		}
	}
	user := cfg.Username
	pass := cfg.Password
	tlsInsecure := cfg.ProxyInsecure
	switch req.URL.Path {
	case "/clash":
		fmt.Fprintf(rw, clashTemp, name, rip, eip, eportStr, rip, rportStr, tls, user, pass, tlsInsecure)
	case "/quan":
		fallthrough
	case "/quanx":
		fmt.Fprintf(rw, quanxTemp, name, rip, eip, eportStr, rip, rportStr, tls, user, pass, !tlsInsecure)
	default:
		http.NotFound(rw, req)
	}
}

func (hp *HTTPProxy) HTTPHandler(rw http.ResponseWriter, req *http.Request) {
	removeProxyHeaders(req)

	resp, err := hp.tp.RoundTrip(req)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	copyHeaders(rw.Header(), resp.Header)
	rw.WriteHeader(resp.StatusCode)

	_, err = io.Copy(rw, resp.Body)
	if err != nil && err != io.EOF {
		return
	}
}

// deprecated
// Hijack needs to SetReadDeadline on the Conn of the request, but if we use stream compression here,
// we may always get i/o timeout error.
func (hp *HTTPProxy) ConnectHandler(rw http.ResponseWriter, req *http.Request) {
	remote, err := hp.dialer.Dial("tcp", req.URL.Host)
	if err != nil {
		http.Error(rw, "Failed", http.StatusBadRequest)
		return
	}
	defer remote.Close()
	hj, ok := rw.(http.Hijacker)
	if !ok {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	client, _, err := hj.Hijack()
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	client.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))

	transport(remote, client)
	client.Close()
}

func (hp *HTTPProxy) Auth(req *http.Request, header string) bool {
	if hp.s.GetCfg().Username == "" && hp.s.GetCfg().Password == "" {
		return true
	}
	u, p, ok := basicAuth(req, header)
	if !ok {
		log.Printf("Authenication Failed: Failed to get auth info.\n")
		return false
	}
	if u != hp.s.GetCfg().Username || p != hp.s.GetCfg().Password {
		log.Printf("Authenication Failed: %s:%s not matched.\n", u, p)
		return false
	}
	return true
}

func basicAuth(req *http.Request, header string) (username, password string, ok bool) {
	auth := req.Header.Get(header)
	if auth == "" {
		return "", "", false
	}
	return parseBasicAuth(auth)
}

// parseBasicAuth parses an HTTP Basic Authentication string.
// "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" returns ("Aladdin", "open sesame", true).
func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	if len(auth) < len(prefix) {
		return "", "", false
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", false
	}
	cs := string(c)
	username, password, ok = strings.Cut(cs, ":")
	if !ok {
		return "", "", false
	}
	return username, password, true
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func removeProxyHeaders(req *http.Request) {
	req.RequestURI = ""
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Connection")
	req.Header.Del("Proxy-Authenticate")
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("TE")
	req.Header.Del("Trailers")
	req.Header.Del("Transfer-Encoding")
	req.Header.Del("Upgrade")
}
