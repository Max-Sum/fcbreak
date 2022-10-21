package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/Max-Sum/fcbreak"
	"github.com/akamensky/argparse"
	"github.com/gin-gonic/gin"
)

func main() {
	parser := argparse.NewParser("natbreaker-reflector", "Reflect connectors info back")
	// Create string flag
	addr := parser.String("l", "listen", &argparse.Options{Help: "HTTP Listening Address"})
	tlsaddr := parser.String("s", "listen-https", &argparse.Options{Help: "HTTPS Listening Address"})
	tlscert := parser.String("", "cert", &argparse.Options{Help: "HTTPS Certificate File"})
	tlskey := parser.String("", "key", &argparse.Options{Help: "HTTPS Private Key File"})
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

	gin.SetMode(gin.ReleaseMode)
	s := fcbreak.NewServer()
	if user != nil {
		s.User = *user
	}
	if pass != nil {
		s.Pass = *pass
	}
	if addr == nil && tlsaddr == nil {
		fmt.Print(parser.Usage(errors.New("listen address is missing")))
		os.Exit(1)
	}
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func(){
		<-c
		// graceful exit
		s.Shutdown()
		os.Exit(0)
	}()
	var wg sync.WaitGroup
	if addr != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.ListenAndServe(*addr, nil)
			if err != nil {
				fmt.Print(err)
			}
		}()
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
		tlsconf := &tls.Config {
			Certificates: []tls.Certificate{cert},
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.ListenAndServe(*tlsaddr, tlsconf)
			if err != nil {
				fmt.Print(err)
			}
		}()
	}
	wg.Wait()
}
