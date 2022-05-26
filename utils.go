package fcbreak

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"

	ua "github.com/mileusna/useragent"
)

type contextKey struct {
	key string
}

var ConnContextKey = &contextKey{"http-conn"}

func SaveConnInContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, ConnContextKey, c)
}

func GetConn(r *http.Request) net.Conn {
	return r.Context().Value(ConnContextKey).(net.Conn)
}

type CloseWriter interface {
	CloseWrite() error
}

type CloseReader interface {
	CloseRead() error
}

func SupportAltSvc(useragent string) bool {
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
