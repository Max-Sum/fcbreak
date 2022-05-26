package fcbreak

type ClientCommonConf struct {
	// ServerAddr specifies the address of the server to connect to. By
	// default, this value is "0.0.0.0".
	ServerAddr string `ini:"server_addr" json:"server_addr"`
	// ServerPort specifies the port to connect to the server on. By default,
	// this value is 7001.
	ServerPort int `ini:"server_port" json:"server_port"`
	// HeartBeatInterval specifies at what interval heartbeats are sent to the
	// server, in seconds. It is not recommended to change this value. By
	// default, this value is 30.
	HeartbeatInterval int64 `ini:"heartbeat_interval" json:"heartbeat_interval"`
	// HeartBeatTimeout specifies the maximum allowed heartbeat response delay
	// before the connection is terminated, in seconds. It is not recommended
	// to change this value. By default, this value is 90.
	HeartbeatTimeout int64 `ini:"heartbeat_timeout" json:"heartbeat_timeout"`
}

func GetDefaultClientConf() ClientCommonConf {
	return ClientCommonConf{
		ServerAddr:        "0.0.0.0",
		ServerPort:        7001,
		HeartbeatInterval: 30,
		HeartbeatTimeout:  90,
	}
}

type ServiceConf struct {
	Scheme          string `ini:"type" json:"type"`
	LocalAddr       string `ini:"local_ip" json:"local_ip"`
	LocalPort       int    `ini:"local_port" json:"local_port"`
	BindAddr        string `ini:"bind_addr" json:"bind_addr"`
	BindPort        int    `ini:"bind_port" json:"bind_port"`
	RemoteAddr      string `ini:"remote_addr" json:"remote_addr"`
	RemotePort      int    `ini:"remote_port" json:"remote_port"`
	HTTPServiceConf `ini:",extends"`
}

type HTTPServiceConf struct {
	CacheTime  int    `ini:"http_cache_time"`
	AltSvc     bool   `ini:"http_altsvc"`
	NIPDomain  string `ini:"http_altsvc_nip_domain"`
	TLSCert    string `ini:"https_crt"`
	TLSKey     string `ini:"https_key"`
	TLSBackend bool   `ini:"https_backend"`
}

func GetDefaultServiceConf() ServiceConf {
	return ServiceConf{
		Scheme:     "tcp",
		LocalAddr:  "localhost",
		LocalPort:  0,
		BindAddr:   "",
		BindPort:   0,
		RemoteAddr: "",
		RemotePort: 0,
		HTTPServiceConf: HTTPServiceConf{
			CacheTime:  300,
			TLSBackend: false,
			TLSCert:    "",
			TLSKey:     "",
			AltSvc:     false,
			NIPDomain:  "",
		},
	}
}
