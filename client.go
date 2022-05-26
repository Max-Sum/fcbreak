package fcbreak

import (
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	reuse "github.com/libp2p/go-reuseport"
)

// Client
type Client struct {
	cfg ClientCommonConf
}

func NewClient(c ClientCommonConf) *Client {
	return &Client{cfg: c}
}

func (c *Client) Start(s *ReqService) error {
	l, err := s.Listen()
	if err != nil {
		return err
	}
	go func() {
		for {
			log.Printf("Register New Service [%s]: %s://%s", s.Name, s.Scheme, s.RemoteAddr)
			err := c.Register(&s.Service, l.Addr().String())
			if err != nil && err != io.EOF {
				log.Printf("Register Error: %v", err)
			}
			log.Printf("Wait 5s...")
			time.Sleep(time.Duration(5)*time.Second)		
			log.Printf("Retrying...")
		}
	}()
	return s.Serve(l)
}

func (c *Client) Register(s *Service, bindAddr string) error {
	serverAddr := fmt.Sprintf("%s:%d", c.cfg.ServerAddr, c.cfg.ServerPort)
	conn, err := reuse.Dial("tcp", bindAddr, serverAddr)
	if err != nil {
		return err
	}
	enc := gob.NewEncoder(conn)
	dec := gob.NewDecoder(conn)
	p := Packet{}
	// Register
	p.PacketType = PACKET_TYPE_REGISTER
	p.ServiceInfo = s
	err = enc.Encode(p)
	if err != nil {
		return err
	}
	// Loop
	for {
		p := Packet{}
		err := dec.Decode(&p)
		if err != nil {
			if err != io.EOF {
				log.Printf("Decode error: %v\n", err)
			}
			break
		}
		switch p.PacketType {
		case PACKET_TYPE_PING:
			p.PacketType = PACKET_TYPE_PONG
			err = enc.Encode(p)
			if err != nil {
				log.Printf("Encode error: %v\n", err)
			}
		case PACKET_TYPE_PONG:
			continue
		case PACKET_TYPE_REFLECT:
			s.mutex.Lock()
			s.ExposedAddr = p.ServiceInfo.ExposedAddr
			s.mutex.Unlock()
		default:
			err = errors.New("unsupported packet type")
		}
		if err != nil {
			break
		}
	}
	return err
}
