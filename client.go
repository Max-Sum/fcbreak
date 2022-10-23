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
}

func NewServiceClient(svc Service, clientCfg *ClientCommonConf) *ServiceClient {
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
	info := c.svc.GetInfo()
	str, err := json.Marshal(info)
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
		return errors.New("Register [" + info.Name + "] error: " + string(by))
	}
	return json.Unmarshal(by, info)
}

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
	if resp.StatusCode != http.StatusOK {
		return errors.New("Refresh [" + info.Name + "] error: " + string(by))
	}
	return json.Unmarshal(by, info)
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
	if resp.StatusCode != http.StatusOK {
		return errors.New("Refresh [" + info.Name + "]'s address error: " + string(by))
	}
	return json.Unmarshal(by, info)
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
	if resp.StatusCode != http.StatusOK {
		return errors.New("Refresh [" + info.Name + "]'s Proxy address error: " + string(by))
	}
	return json.Unmarshal(by, info)
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
	if resp.StatusCode != http.StatusOK {
		by, _ := io.ReadAll(resp.Body)
		return errors.New("Delete [" + info.Name + "] error: " + string(by))
	}
	return nil
}

func (c *ServiceClient) refreshTimer(exitCh chan struct{}) error {
	refreshProxy := c.svc.GetInfo().Scheme == "http" || c.svc.GetInfo().Scheme == "https"
	for {
		select {
		case <-time.After(time.Duration(c.cfg.HeartbeatInterval) * time.Second):
			err := c.refreshAddr()
			if err == nil && refreshProxy {
				err = c.refreshProxyAddr()
			}
			if err != nil {
				return err
			}
		case <-c.stopCh:
			return nil
		case <-exitCh:
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
	return reuse.Dial("tcp", c.pListener.Addr().String(), addr)
}

func (c *ServiceClient) Start(force bool) error {
	info := c.svc.GetInfo()
	if c.svc.GetCfg().BindPort != 0 {
		// Checking port availability
		l, err := listenForService(c.svc)
		if err != nil {
			return err
		}
		c.listener = l
	}
	// Retry Loop
	go func() {
		listenProxy := info.Scheme == "http" || info.Scheme == "https"
		for {
			var err error
			retryCh := make(chan struct{}) // channel to see if an retry is triggered
			errCh := make(chan error)
			// Listen
			if c.listener == nil {
				if c.listener, err = listenForService(c.svc); err != nil {
					log.Printf("Failed to listen for [%s]: %v.", info.Name, err)
				}
			}
			if err == nil && listenProxy {
				if c.pListener, err = listenProxyForService(c.svc); err != nil {
					log.Printf("Failed to listen for [%s]: %v.", info.Name, err)
				}
			}
			// Register
			if err == nil {
				if err = c.register(); err != nil {
					log.Printf("Failed to register [%s]: %v.", info.Name, err)
					if force {
						log.Printf("Delete existing [%s].", info.Name)
						if err := c.delete(); err != nil {
							log.Printf("Failed to delete [%s]: %v.", info.Name, err)
						} else {
							if err = c.register(); err != nil {
								log.Printf("Failed to register [%s]: %v.", info.Name, err)
							}
						}
					}
				}
			}
			// Update proxy addr
			if err == nil && listenProxy {
				if err = c.refreshProxyAddr(); err != nil {
					log.Printf("Failed to set proxy_addr [%s]: %v.", info.Name, err)
				}
			}
			// Serve
			wg := sync.WaitGroup{} // Wait for all serving routines
			if err == nil {
				log.Printf("Service [%s] registered.", info.Name)

				wg.Add(1)
				go func() {
					err := c.svc.Serve(c.listener)
					select {
					case <-retryCh:
					case <-c.stopCh:
					default:
						log.Printf("Failed when serving [%s]: %v.", info.Name, err)
						errCh <- err
					}
					wg.Done()
				}()
				if listenProxy {
					wg.Add(1)
					go func() {
						err := c.svc.Serve(c.pListener)
						select {
						case <-retryCh:
						case <-c.stopCh:
						default:
							log.Printf("Failed when serving [%s]: %v.", info.Name, err)
							errCh <- err
						}
						wg.Done()
					}()
				}
				wg.Add(1)
				go func() {
					if err = c.refreshTimer(retryCh); err != nil {
						log.Printf("Failed when refreshing [%s]: %v.", info.Name, err)
						errCh <- err
					}
					wg.Done()
				}()

				err = <-errCh
				select {
				case <-c.stopCh:
					return
				default:
				}
			}
			if err != nil {
				time.Sleep(3 * time.Second)
			}
			// stop on listening
			close(retryCh)
			close(errCh)
			if c.listener != nil {
				c.listener.Close()
				c.listener = nil
			}
			if c.pListener != nil {
				c.pListener.Close()
				c.pListener = nil
			}
			wg.Wait()
			c.client.CloseIdleConnections()
			if listenProxy {
				c.pClient.CloseIdleConnections()
			}
			log.Printf("Retrying [%s].", info.Name)
		}
	}()

	return nil
}

func (c *ServiceClient) Stop(ctx context.Context) error {
	c.delete()
	close(c.stopCh)
	return c.svc.Shutdown(ctx)
}
