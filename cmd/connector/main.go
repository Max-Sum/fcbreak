package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Max-Sum/fcbreak"
	"github.com/akamensky/argparse"
	"github.com/coreos/go-iptables/iptables"
)

var (
	TempChainName = "FCBREAK-CONNECTOR-TEMP"
	ChainName     = "FCBREAK-CONNECTOR"
)

func main() {
	parser := argparse.NewParser("fcbreak-connector", "Retrive address and write to iptables, Linux only currently")
	// Create string flag
	server := parser.String("s", "server", &argparse.Options{Required: true, Help: "Server Address, including protocol and user/pass"})
	interval := parser.Int("i", "interval", &argparse.Options{Default: 300, Help: "Interval between updates in seconds"})
	// Parse input
	err := parser.Parse(os.Args)
	if err != nil {
		// In case of error print error and print usage
		// This can also be done by passing -h or --help flags
		fmt.Print(parser.Usage(err))
		os.Exit(1)
	}

	serverUrl, err := url.Parse(*server)
	if err != nil {
		log.Printf("Failed to parse server URL: %v\n", err)
	}
	serverHostname := serverUrl.Hostname()

	// Gracefully Stop
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	for {
		svcs, err := RefreshServices(*server)
		if err != nil {
			return
		}
		err = UpdateIPTables(svcs, serverHostname)
		if err != nil {
			log.Printf("Update iptables error: %v\n", err)
		}
		select {
		case <-time.After(time.Duration(*interval) * time.Second):
			svcs, err = RefreshServices(*server)
			if err != nil {
				return
			}
			err = UpdateIPTables(svcs, serverHostname)
			if err != nil {
				log.Printf("Update iptables error: %v\n", err)
			}
		case <-sigc:
			ClearIPTables()
			return
		}
	}
}

func RefreshServices(server string) (map[string]*fcbreak.ServiceInfo, error) {
	svcs := make(map[string]*fcbreak.ServiceInfo)
	addr := fmt.Sprintf("%s/services", server)
	req, err := http.NewRequest("GET", addr, nil)
	if err != nil {
		log.Printf("HTTP new request error: %v\n", err)
		return svcs, err
	}
	// Update svcs
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("HTTP Get error: %v\n", err)
		return svcs, err
	}
	by, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("HTTP Body error: %v\n", err)
		return svcs, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("HTTP error: %s\n", string(by))
		return svcs, err
	}
	if err := json.Unmarshal(by, &svcs); err != nil {
		log.Printf("JSON parsing: %v\n", err)
		return svcs, err
	}
	log.Println("Successfully retrieve services.")
	return svcs, nil
}

func UpdateIPTables(svcs map[string]*fcbreak.ServiceInfo, serverHostname string) error {
	// Server IP
	ips, err := net.LookupIP(serverHostname)
	if err != nil {
		return err
	}
	// Update iptables
	ipt, err := iptables.New(iptables.IPFamily(iptables.ProtocolIPv4))
	if err != nil {
		log.Fatalf("Failed to new up an IPtables intance: %v", err)
	}
	if exists, err := ipt.ChainExists("nat", "OUTPUT"); !exists || err != nil {
		log.Fatalf("iptables nat OUTPUT chain doesn't exists, possibly a permission problem.")
	}
	if exists, err := ipt.ChainExists("nat", "PREROUTING"); !exists || err != nil {
		log.Fatalf("iptables nat PREROUTING chain doesn't exists, possibly a permission problem.")
	}
	// Write in Temp chain
	if err = ipt.NewChain("nat", TempChainName); err != nil {
		return err
	}
	defer ipt.ClearAndDeleteChain("nat", TempChainName)
	for name, svc := range svcs {
		if svc.RemoteAddr == "" {
			continue
		}
		remote_ip, remote_port, err := net.SplitHostPort(svc.RemoteAddr)
		if err != nil {
			return err
		}
		// IPv4 only now
		if remote_ip == "" || remote_ip == "0.0.0.0" || remote_ip == "[::]" {
			for _, ip := range ips {
				ipv4 := ip.To4()
				if ipv4 == nil {
					continue
				}
				err = ipt.AppendUnique("nat", TempChainName, "-p", "tcp", "-d", ipv4.String(), "--dport", remote_port, "-j", "DNAT", "--to-destination", svc.ExposedAddr)
				if err != nil {
					return err
				}
			}
		} else {
			err = ipt.AppendUnique("nat", TempChainName, "-p", "tcp", "-d", remote_ip, "--dport", remote_port, "-j", "DNAT", "--to-destination", svc.ExposedAddr)
			if err != nil {
				return err
			}
		}
		log.Printf("Successfully Update Service [%s]\n", name)
	}
	// Replace Old Chain
	exists, err := ipt.ChainExists("nat", ChainName)
	if err != nil {
		return err
	}
	if exists {
		ipt.DeleteIfExists("nat", "OUTPUT", "-j", ChainName)
		ipt.DeleteIfExists("nat", "PREROUTING", "-j", ChainName)
		if err = ipt.ClearAndDeleteChain("nat", ChainName); err != nil {
			return err
		}
	}
	if err = ipt.RenameChain("nat", TempChainName, ChainName); err != nil {
		return err
	}
	// Direct flow
	if err = ipt.AppendUnique("nat", "PREROUTING", "-j", ChainName); err != nil {
		return err
	}
	if err = ipt.AppendUnique("nat", "OUTPUT", "-j", ChainName); err != nil {
		return err
	}
	return nil
}

func ClearIPTables() {
	// Update iptables
	ipt, err := iptables.New(iptables.IPFamily(iptables.ProtocolIPv4))
	if err != nil {
		log.Fatalf("Failed to new up an IPtables intance: %v", err)
	}
	ipt.DeleteIfExists("nat", "OUTPUT", "-j", ChainName)
	ipt.DeleteIfExists("nat", "PREROUTING", "-j", ChainName)
	exists, _ := ipt.ChainExists("nat", ChainName)
	if exists {
		ipt.ClearAndDeleteChain("nat", ChainName)
	}
	exists, _ = ipt.ChainExists("nat", TempChainName)
	if exists {
		ipt.ClearAndDeleteChain("nat", TempChainName)
	}
}
