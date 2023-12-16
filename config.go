package fcbreak

type ClientCommonConf struct {
	// ServerAddr specifies the address of the server to connect to. By
	// default, this value is "http://0.0.0.0:7001".
	Server string `ini:"server" json:"server"`
	// SkipTLSVerify willl skip the check of TLS certificates.
	SkipTLSVerify bool `ini:"skip_verify" json:"skip_verify"`
	// HeartBeatInterval specifies at what interval heartbeats are sent to the
	// server, in seconds. It is not recommended to change this value. By
	// default, this value is 30.
	HeartbeatInterval int64 `ini:"heartbeat_interval" json:"heartbeat_interval"`
	// HeartBeatTimeout specifies the maximum allowed heartbeat response delay
	// before the connection is terminated, in seconds. It is not recommended
	// to change this value. By default, this value is 90.
	HeartbeatTimeout int64 `ini:"heartbeat_timeout" json:"heartbeat_timeout"`
	// RequestTimeout specifies the timeout for any API request in seconds.
	// By default, this value is 5.
	RequestTimeout int64 `ini:"request_timeout" json:"request_timeout"`
	// UseIPv6 specifies if the connection to server should use IPv6 instead of IPv4.
	// By default, this value is false.
	UseIPv6 bool `ini:"use_ipv6" json:"use_ipv6"`
	// ServiceInfoPath specifies a directory for service info to be saved to.
	// External services can obtain the exposed address and port from the file.
	// By default, this value is /run/fcbreak/services/
	ServicesInfoPath string `ini:"services_info_path" json:"services_info_path"`
}

func GetDefaultClientConf() ClientCommonConf {
	return ClientCommonConf{
		Server:            "http://0.0.0.0:7001",
		SkipTLSVerify:     false,
		HeartbeatInterval: 30,
		HeartbeatTimeout:  90,
		RequestTimeout:    5,
		UseIPv6:           false,
		ServicesInfoPath:  "/run/fcbreak/services",
	}
}

type ServiceConf struct {
	Name            string `ini:"-" json:"name"`
	Scheme          string `ini:"type" json:"type"`
	LocalAddr       string `ini:"local_ip" json:"local_ip"`
	LocalPort       uint16 `ini:"local_port" json:"local_port"`
	BindAddr        string `ini:"bind_addr" json:"bind_addr"`
	BindPort        uint16 `ini:"bind_port" json:"bind_port"`
	RemoteAddr      string `ini:"remote_addr" json:"remote_addr"`
	RemotePort      uint16 `ini:"remote_port" json:"remote_port"`
	HTTPServiceConf `ini:",extends"`
}

type HTTPServiceConf struct {
	Hostname      string `ini:"http_hostname"`
	Username      string `ini:"http_username"`
	Password      string `ini:"http_password"`
	CacheTime     int    `ini:"http_cache_time"`
	Redirect      bool   `ini:"http_redirect"`
	AltSvc        bool   `ini:"http_altsvc"`
	DDNSDomain    string `ini:"http_ddns_domain"`
	NIPDomain     string `ini:"http_nip_domain"`
	Backend       string `ini:"http_backend"`
	ChainProxy    string `ini:"http_proxy_chain"`
	TLSCert       string `ini:"https_crt"`
	TLSKey        string `ini:"https_key"`
	ProxyInsecure bool   `ini:"https_proxy_skip_cert_verification"`
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
			Username:      "",
			Password:      "",
			CacheTime:     300,
			ChainProxy:    "",
			Backend:       "http",
			TLSCert:       "",
			TLSKey:        "",
			Redirect:      true,
			AltSvc:        false,
			ProxyInsecure: false,
			NIPDomain:     "",
		},
	}
}
