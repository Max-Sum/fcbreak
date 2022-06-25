package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Max-Sum/fcbreak"
	"github.com/akamensky/argparse"
)

var svcs map[string]*fcbreak.ReqService

func main() {
	parser := argparse.NewParser("natbreaker-client", "Reflect connectors info back")
	// Create string flag
	cfgpath := parser.String("c", "Config", &argparse.Options{Required: true, Help: "Config File"})
	// Parse input
	err := parser.Parse(os.Args)
	if err != nil {
		// In case of error print error and print usage
		// This can also be done by passing -h or --help flags
		fmt.Print(parser.Usage(err))
		os.Exit(1)
	}
	commonCfg, err := UnmarshalClientConfFromIni(*cfgpath)
	if err != nil {
		log.Fatalf("%v", err)
		os.Exit(2)
	}
	serverCfgs, err := LoadAllProxyConfsFromIni(*cfgpath)
	if err != nil {
		log.Fatalf("%v", err)
		os.Exit(2)
	}

	svcs = make(map[string]*fcbreak.ReqService)

	defer func() {
		for _, svc := range svcs {
			svc.Stop()
		}
	}()

	// Start Client
	for k, v := range serverCfgs {
		svc := fcbreak.NewReqService(k, v, &commonCfg)
		err := svc.Start()
		if err != nil {
			log.Printf("%v", err)
			return
		}
		svcs[svc.Name] = svc
	}

	log.Println("Up and running.")

	// Gracefully Stop
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)

	<-sigc
	log.Println("Exiting...")
}
