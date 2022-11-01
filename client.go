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
	"sync"
	"time"

	reuse "github.com/libp2p/go-reuseport"
)

type ServiceClient struct {
	svc       Service
	listener  net.Listener
	pListener net.Listener
	client    *http.Client
	pClient   *http.Client
	cfg       *ClientCommonConf
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

func NewServiceClient(svc Service, clientCfg *ClientCommonConf) *ServiceClient {
	c := &ServiceClient{
		svc: svc,
		cfg: clientCfg,
		client: &http.Client{
			Timeout: time.Duration(clientCfg.RequestTimeout * int64(time.Second)),
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
	if c.listenProxy() {
		c.pClient = &http.Client{
			Timeout: time.Duration(clientCfg.RequestTimeout * int64(time.Second)),
			Transport: &http.Transport{
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
			},
		}
	}
	return c
}

// func (c *ServiceClient) register() error {
// 	addr := fmt.Sprintf("%s/services", c.cfg.Server)
// 	info := c.svc.GetInfo()
// 	str, err := json.Marshal(info)
// 	if err != nil {
// 		return err
// 	}
// 	b := bytes.NewBuffer(str)
// 	req, err := http.NewRequest("POST", addr, b)
// 	if err != nil {
// 		return err
// 	}
// 	resp, err := c.client.Do(req)
// 	if err != nil {
// 		return err
// 	}
// 	defer resp.Body.Close()
// 	by, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		return err
// 	}
// 	if resp.StatusCode < 200 || resp.StatusCode > 299 {
// 		return errors.New("Register [" + info.Name + "] error: " + string(by))
// 	}
// 	return json.Unmarshal(by, info)
// }

func (c *ServiceClient) refresh() error {
	// Update Service
	info := c.svc.GetInfo()
	addr := fmt.Sprintf("%s/services/%s", c.cfg.Server, info.Name)
	str, err := json.Marshal(info)
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
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return errors.New("Refresh [" + info.Name + "] error: " + string(by))
	}
	rcvInfo := ServiceInfo{}
	if err := json.Unmarshal(by, &rcvInfo); err != nil {
		return err
	}
	c.svc.SetExposedAddr(rcvInfo.ExposedAddr)
	return nil
}

func (c *ServiceClient) refreshAddr() error {
	// Update Service's exposed address
	info := c.svc.GetInfo()
	addr := fmt.Sprintf("%s/services/%s/addr", c.cfg.Server, info.Name)
	req, err := http.NewRequest("PUT", addr, nil)
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
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return errors.New("Refresh [" + info.Name + "]'s address error: " + string(by))
	}
	rcvInfo := ServiceInfo{}
	if err := json.Unmarshal(by, &rcvInfo); err != nil {
		return err
	}
	c.svc.SetExposedAddr(rcvInfo.ExposedAddr)
	return nil
}

func (c *ServiceClient) refreshProxyAddr() error {
	// Update Service's Proxy protocol address
	info := c.svc.GetInfo()
	addr := fmt.Sprintf("%s/services/%s/proxy_addr", c.cfg.Server, info.Name)
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
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return errors.New("Refresh [" + info.Name + "]'s Proxy address error: " + string(by))
	}
	return nil
}

func (c *ServiceClient) delete() error {
	info := c.svc.GetInfo()
	addr := fmt.Sprintf("%s/services/%s", c.cfg.Server, info.Name)
	req, err := http.NewRequest("DELETE", addr, nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		by, _ := io.ReadAll(resp.Body)
		return errors.New("Delete [" + info.Name + "] error: " + string(by))
	}
	return nil
}

func (c *ServiceClient) listen() (err error) {
	info := c.svc.GetInfo()
	if c.listener == nil {
		if c.listener, err = listenForService(c.svc); err != nil {
			log.Printf("Failed to listen for [%s]: %v.", info.Name, err)
			return
		}
	}
	if c.listenProxy() {
		if c.pListener, err = listenProxyForService(c.svc); err != nil {
			log.Printf("Failed to listen for [%s] (Proxy protcol): %v.", info.Name, err)
			return
		}
	}
	return
}

// serve will serve for the service
func (c *ServiceClient) serve(ctx context.Context) (err error) {
	info := c.svc.GetInfo()
	internalCtx, cancel := context.WithCancel(ctx)
	errCh := make(chan error)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := c.svc.Serve(c.listener)
		select {
		case <-internalCtx.Done():
		case <-c.stopCh:
		default:
			log.Printf("Failed when serving [%s]: %v.", info.Name, err)
			errCh <- err
		}
	}()
	if c.listenProxy() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := c.svc.Serve(c.pListener)
			select {
			case <-internalCtx.Done():
			case <-c.stopCh:
			default:
				log.Printf("Failed when serving [%s]: %v.", info.Name, err)
				errCh <- err
			}
		}()
	}
	select {
	case <-ctx.Done():
	case err = <-errCh:
	}
	cancel()
	c.listener.Close()
	c.listener = nil
	if c.pListener != nil {
		c.pListener.Close()
		c.pListener = nil
	}
	wg.Wait()
	return err
}

func (c *ServiceClient) register() error {
	info := c.svc.GetInfo()
	// Register
	if err := c.refresh(); err != nil {
		log.Printf("Failed to register [%s]: %v.", info.Name, err)
		return err
	}
	// Update proxy addr
	if c.listenProxy() {
		if err := c.refreshProxyAddr(); err != nil {
			log.Printf("Failed to set proxy_addr [%s]: %v.", info.Name, err)
			return err
		}
	}
	return nil
}

func (c *ServiceClient) refreshAPI(ctx context.Context) error {
	for {
		select {
		case <-time.After(time.Duration(c.cfg.HeartbeatInterval) * time.Second):
			if err := c.refreshAddr(); err != nil {
				return err
			}
			if c.listenProxy() {
				if err := c.refreshProxyAddr(); err != nil {
					return err
				}
			}
		case <-c.stopCh:
			return nil
		case <-ctx.Done():
			return nil
		}
	}
}

// Use the binded address to dial
func (c *ServiceClient) DialBindAddr(ctx context.Context, network string, addr string) (net.Conn, error) {
	nla, err := reuse.ResolveAddr(network, c.listener.Addr().String())
	if err != nil {
		return nil, fmt.Errorf("failed to resolve local addr: %w", err)
	}
	d := net.Dialer{
		Control:   reuse.Control,
		LocalAddr: nla,
	}
	return d.DialContext(ctx, network, addr)
}

// Use the binded address to dial
func (c *ServiceClient) DialProxyAddr(ctx context.Context, network string, addr string) (net.Conn, error) {
	nla, err := reuse.ResolveAddr(network, c.pListener.Addr().String())
	if err != nil {
		return nil, fmt.Errorf("failed to resolve local addr: %w", err)
	}
	d := net.Dialer{
		Control:   reuse.Control,
		LocalAddr: nla,
	}
	return d.DialContext(ctx, network, addr)
}

func (c *ServiceClient) Start(force bool) error {
	info := c.svc.GetInfo()
	if c.svc.GetCfg().BindPort != 0 {
		// Checking port availability
		if err := c.listen(); err != nil {
			return err
		}
	}
	// Retry Loop
	go func() {
		for {
			if err := c.listen(); err != nil {
				continue
			}
			retryCtx, cancel := context.WithCancel(context.Background())
			errCh := make(chan error)
			c.wg.Add(1)
			go func() {
				defer c.wg.Done()
				err := c.serve(retryCtx)
				if err != nil {
					select {
					case <-c.stopCh:
					case <-retryCtx.Done():
					default:
						errCh <- err
					}
				}
			}()
			c.wg.Add(1)
			go func() {
				// retry api operations without restarting listen
				defer c.wg.Done()
				errCount := 0
				for {
					err := c.register()
					if err != nil {
						errCount += 1
					} else {
						errCount = 0
						c.refreshAPI(retryCtx)
					}
					select {
					case <-c.stopCh:
						return
					case <-retryCtx.Done():
						return
					default:
					}
					if errCount >= 5 {
						log.Printf("Too many error on register [%s], restarting.", info.Name)
						errCh <- err
						return
					}
					time.Sleep(3 * time.Second)
				}
			}()
			select {
			case <-c.stopCh:
				cancel()
				return
			case <-errCh:
				log.Printf("Error on service [%s], wait for retry.", info.Name)
				time.Sleep(3 * time.Second)
			}
			cancel()
			close(errCh)
			c.wg.Wait()
			c.client.CloseIdleConnections()
			if c.pClient != nil {
				c.pClient.CloseIdleConnections()
			}
			log.Printf("Retrying [%s].", info.Name)
		}
	}()

	return nil
}

func (c *ServiceClient) Stop(ctx context.Context) error {
	close(c.stopCh)
	c.wg.Wait()
	c.delete()
	c.client.CloseIdleConnections()
	if c.pClient != nil {
		c.pClient.CloseIdleConnections()
	}
	return c.svc.Shutdown(ctx)
}

func (c *ServiceClient) listenProxy() bool {
	cfg := c.svc.GetCfg()
	return cfg.Scheme == "http" || cfg.Scheme == "https"
}

// func (c *ServiceClient) stopping() bool {
// 	select {
// 	case <-c.stopCh:
// 		return true
// 	default:
// 	}
// 	return false
// }
