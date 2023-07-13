package fcbreak

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"

	ua "github.com/mileusna/useragent"
)

type contextKey struct {
	key string
}

var connContextKey = &contextKey{"http-conn"}
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 32*1024)
	},
}

func saveConnInContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connContextKey, c)
}

func getConn(r *http.Request) net.Conn {
	return r.Context().Value(connContextKey).(net.Conn)
}

func getConnUnwarpTLS(r *http.Request) net.Conn {
	conn := getConn(r)
	if tc, ok := conn.(*tls.Conn); ok {
		return tc.NetConn()
	}
	return conn
}

func transport(rw1, rw2 io.ReadWriter) error {
	errc := make(chan error, 1)
	go func() {
		errc <- copyBuffer(rw1, rw2)
	}()

	go func() {
		errc <- copyBuffer(rw2, rw1)
	}()

	if err := <-errc; err != nil && err != io.EOF {
		return err
	}

	return nil
}

func copyBuffer(dst io.Writer, src io.Reader) error {
	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	_, err := io.CopyBuffer(dst, src, buf)
	return err
}

func supportAltSvc(useragent string) bool {
	a := ua.Parse(useragent)
	ver_str := strings.Split(a.Version, ".")
	var v []int
	for _, ver := range ver_str {
		v_int, err := strconv.Atoi(ver)
		if err != nil {
			v_int = 0
		}
		v = append(v, v_int)
	}
	if a.IsChrome() && v[0] > 79 {
		return true
	}
	if a.IsEdge() && v[0] > 79 {
		return true
	}
	if a.IsSafari() {
		return true
	}
	if a.IsFirefox() && v[0] > 38 {
		return true
	}
	if a.IsOpera() && v[0] > 81 {
		return true
	}
	return false
}

// onceCloseListener wraps a net.Listener, protecting it from
// multiple Close calls.
type onceCloseListener struct {
	net.Listener
	once sync.Once
}

func (oc *onceCloseListener) Close() (err error) {
	oc.once.Do(func() {
		err = oc.Listener.Close()
	})
	return
}

func verifyHostname(hostname string) bool {
	var ok bool
	if strings.HasPrefix(hostname, "*") {
		ok, _ = regexp.MatchString(`^[a-zA-Z0-9\.]+$`, hostname[1:])
	} else if strings.HasSuffix(hostname, "*") {
		ok, _ = regexp.MatchString(`^[a-zA-Z0-9\.]+$`, hostname[:len(hostname)-1])
	} else {
		ok, _ = regexp.MatchString(`^[a-zA-Z0-9\.]+$`, hostname)
	}
	return ok
}
