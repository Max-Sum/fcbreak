package main

import (
	"fmt"
	"os"

	"github.com/Max-Sum/fcbreak"
	"github.com/akamensky/argparse"
)

func main() {
	parser := argparse.NewParser("natbreaker-reflector", "Reflect connectors info back")
	// Create string flag
	addr := parser.String("l", "listen", &argparse.Options{Required: true, Help: "Listening Address"})
	//webAddr := parser.String("w", "string", &argparse.Options{Required: true, Help: "Web Listening Address"})
	// Parse input
	err := parser.Parse(os.Args)
	if err != nil {
		// In case of error print error and print usage
		// This can also be done by passing -h or --help flags
		fmt.Print(parser.Usage(err))
		os.Exit(1)
	}
	s := fcbreak.NewServer()
	s.ListenAndServe(*addr)
}
