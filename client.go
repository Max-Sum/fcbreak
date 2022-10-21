package fcbreak

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	reuse "github.com/libp2p/go-reuseport"
)

type ServiceClient struct {
	svc      *Service
	listener *svcInitMuxListener
	client   *http.Client
	pClient  *http.Client
	cfg      *ClientCommonConf
	stopCh   chan (struct{})
}

func NewServiceClient(svc *Service, clientCfg *ClientCommonConf) *ServiceClient {
	c := &ServiceClient{
		svc: svc,
		cfg: clientCfg,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		pClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		stopCh: make(chan struct{}),
	}
	c.client.Transport = &http.Transport{
		Proxy:               nil,
		DialContext:         c.DialBindAddr,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: 0,
		MaxConnsPerHost:     0,
		IdleConnTimeout:     120 * time.Second,
		DisableKeepAlives:   false,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: clientCfg.SkipTLSVerify,
		},
	}
	c.pClient.Transport = &http.Transport{
		Proxy:               nil,
		DialContext:         c.DialProxyAddr,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: 0,
		MaxConnsPerHost:     0,
		IdleConnTimeout:     120 * time.Second,
		DisableKeepAlives:   false,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: clientCfg.SkipTLSVerify,
		},
	}
	return c
}

func (c *ServiceClient) register() error {
	addr := fmt.Sprintf("%s/services", c.cfg.Server)
	str, err := json.Marshal(c.svc.ServiceInfo)
	if err != nil {
		return err
	}
	b := bytes.NewBuffer(str)
	req, err := http.NewRequest("POST", addr, b)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	by, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New("Register [" + c.svc.Name + "] error: " + string(by))
	}
	return json.Unmarshal(by, &c.svc.ServiceInfo)
}

func (c *ServiceClient) refresh() error {
	// Update Service
	addr := fmt.Sprintf("%s/services/%s", c.cfg.Server, c.svc.Name)
	str, err := json.Marshal(c.svc.ServiceInfo)
	if err != nil {
		return err
	}
	b := bytes.NewBuffer(str)
	req, err := http.NewRequest("PUT", addr, b)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	by, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New("Refresh [" + c.svc.Name + "] error: " + string(by))
	}
	return json.Unmarshal(by, &c.svc.ServiceInfo)
}

func (c *ServiceClient) refreshAddr() error {
	// Update Service's exposed address
	addr := fmt.Sprintf("%s/services/%s/addr", c.cfg.Server, c.svc.Name)
	req, err := http.NewRequest("PUT", addr, nil)
	if err != nil {
		return err
	}
	resp, err := c.pClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	by, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New("Refresh [" + c.svc.Name + "]'s address error: " + string(by))
	}
	return json.Unmarshal(by, &c.svc.ServiceInfo)
}

func (c *ServiceClient) refreshProxyAddr() error {
	// Update Service's Proxy protocol address
	addr := fmt.Sprintf("%s/services/%s/proxy_addr", c.cfg.Server, c.svc.Name)
	req, err := http.NewRequest("PUT", addr, nil)
	if err != nil {
		return err
	}
	resp, err := c.pClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	by, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New("Refresh [" + c.svc.Name + "]'s Proxy address error: " + string(by))
	}
	return json.Unmarshal(by, &c.svc.ServiceInfo)
}

func (c *ServiceClient) delete() error {
	addr := fmt.Sprintf("%s/services/%s", c.cfg.Server, c.svc.Name)
	req, err := http.NewRequest("DELETE", addr, nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		by, _ := io.ReadAll(resp.Body)
		return errors.New("Delete [" + c.svc.Name + "] error: " + string(by))
	}
	return nil
}

func (c *ServiceClient) refreshTimer() error {
	for {
		select {
		case <-time.After(time.Duration(c.cfg.HeartbeatInterval) * time.Second):
			err := c.refreshAddr()
			if err == nil && c.svc.Scheme == "http" || c.svc.Scheme == "https" {
				err = c.refreshProxyAddr()
			}
			if err != nil {
				return err
			}
		case <-c.stopCh:
			return nil
		}
	}
}

// Use the binded address to dial
func (c *ServiceClient) DialBindAddr(_ context.Context, network string, addr string) (net.Conn, error) {
	return reuse.Dial("tcp", c.listener.Addr().String(), addr)
}

// Use the binded address to dial
func (c *ServiceClient) DialProxyAddr(_ context.Context, network string, addr string) (net.Conn, error) {
	return reuse.Dial("tcp", c.listener.pListener.Addr().String(), addr)
}

func (c *ServiceClient) Start(force bool) error {
	l, err := c.svc.Listen()
	if err != nil {
		return err
	}
	c.listener = l.(*svcInitMuxListener)
	go c.svc.Serve(c.listener)
	// Register Loop
	go func() {
		for {
			var err error
			if err = c.register(); err != nil {
				log.Printf("Failed to register [%s]: %v.", c.svc.Name, err)
				if force {
					log.Printf("Delete existing [%s].", c.svc.Name)
					c.delete()
				}
			}
			if err == nil && c.svc.Scheme == "http" || c.svc.Scheme == "https" {
				if err = c.refreshProxyAddr(); err != nil {
					log.Printf("Failed to set proxy_addr [%s]: %v.", c.svc.Name, err)
				}
			}
			if err == nil {
				log.Printf("Service [%s] registered.", c.svc.Name)
				err = c.refreshTimer()
				if err != nil {
					log.Printf("Failed on refreshing [%s]: %v.", c.svc.Name, err)
				} else {
					// Shutdown
					return
				}
			}
			time.Sleep(3 * time.Second)
			log.Printf("Retrying [%s].", c.svc.Name)
		}
	}()

	return nil
}

func (c *ServiceClient) Stop() error {
	c.delete()
	c.stopCh <- struct{}{}
	return c.svc.Shutdown()
}
