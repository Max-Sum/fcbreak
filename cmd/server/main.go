package main

import (
	"fmt"
	"os"

	"github.com/Max-Sum/fcbreak"
	"github.com/akamensky/argparse"
	"github.com/gin-gonic/gin"
)

func main() {
	parser := argparse.NewParser("natbreaker-reflector", "Reflect connectors info back")
	// Create string flag
	addr := parser.String("l", "listen", &argparse.Options{Required: true, Help: "Listening Address"})
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
	s.ListenAndServe(*addr)
}
