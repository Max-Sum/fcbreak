package main

import (
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/Max-Sum/fcbreak"
	"github.com/akamensky/argparse"
)

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
	// Create Client
	var wg sync.WaitGroup
	client := fcbreak.NewClient(commonCfg)
	for k, v := range serverCfgs {
		wg.Add(1)
		svc := fcbreak.NewReqService(k, v, &commonCfg)
		go func() {
			err := client.Start(svc)
			if err != nil {
				log.Fatalf("%v", err)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}
