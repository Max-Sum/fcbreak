package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Max-Sum/fcbreak"
	"github.com/akamensky/argparse"
	"github.com/gin-gonic/gin"
	proxyproto "github.com/pires/go-proxyproto"
	"golang.org/x/net/context"
)

func main() {
	parser := argparse.NewParser("natbreaker-reflector", "Reflect connectors info back")
	// Create string flag
	addr := parser.String("l", "listen", &argparse.Options{Help: "HTTP Listening Address"})
	tlsaddr := parser.String("s", "listen-https", &argparse.Options{Help: "HTTPS Listening Address"})
	tlscert := parser.String("", "cert", &argparse.Options{Help: "HTTPS Certificate File"})
	tlskey := parser.String("", "key", &argparse.Options{Help: "HTTPS Private Key File"})
	proxy := parser.Flag("", "proxy-protocol", &argparse.Options{Help: "Listen with proxy protocol"})
	user := parser.String("u", "user", &argparse.Options{Help: "Authentication Username"})
	pass := parser.String("p", "pass", &argparse.Options{Help: "Authentication Password"})
	// Parse input
	err := parser.Parse(os.Args)
	if err != nil {
		// In case of error print error and print usage
		// This can also be done by passing -h or --help flags
		fmt.Print(parser.Usage(err))
		os.Exit(1)
	}

	var tlsconf *tls.Config
	username := ""
	password := ""
	if user != nil {
		username = *user
	}
	if pass != nil {
		password = *pass
	}
	if addr == nil && tlsaddr == nil {
		fmt.Print(parser.Usage(errors.New("listen address is missing")))
		os.Exit(1)
	}
	if tlsaddr != nil {
		if tlscert == nil || tlskey == nil {
			fmt.Print(parser.Usage(errors.New("tls cert or key is missing")))
			os.Exit(1)
		}
		cert, err := tls.LoadX509KeyPair(*tlscert, *tlskey)
		if err != nil {
			fmt.Print(parser.Usage(err))
			os.Exit(1)
		}
		tlsconf = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}

	gin.SetMode(gin.ReleaseMode)
	s := fcbreak.NewServer(username, password, tlsconf)
	useProxyProto := proxy != nil && *proxy

	errCh := make(chan error)

	if addr != nil {
		go func() {
			ln, err := net.Listen("tcp", *addr)
			if err != nil {
				errCh <- err
				return
			}
			if useProxyProto {
				ln = &proxyproto.Listener{Listener: ln}
			}
			err = s.Serve(ln)
			if err != nil && err != http.ErrServerClosed {
				errCh <- err
			}
		}()
	}
	if tlsaddr != nil {
		go func() {
			ln, err := net.Listen("tcp", *tlsaddr)
			if err != nil {
				fmt.Print(err)
				errCh <- err
				return
			}
			if useProxyProto {
				ln = &proxyproto.Listener{Listener: ln}
			}
			err = s.ServeTLS(ln)
			if err != nil && err != http.ErrServerClosed {
				errCh <- err
			}
		}()
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	select {
	case <-errCh:
		fmt.Print(err)
		os.Exit(1)
	case <-c:
	}
	// graceful exit
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	s.Shutdown(ctx)
	cancel()
}
