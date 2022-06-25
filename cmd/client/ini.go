package main

import (
	"fmt"
	"strings"

	"github.com/Max-Sum/fcbreak"
	"gopkg.in/ini.v1"
)

// Supported sources including: string(file path), []byte, Reader interface.
func UnmarshalClientConfFromIni(source interface{}) (fcbreak.ClientCommonConf, error) {
	f, err := ini.LoadSources(ini.LoadOptions{
		Insensitive:         false,
		InsensitiveSections: false,
		InsensitiveKeys:     false,
		IgnoreInlineComment: true,
		AllowBooleanKeys:    true,
	}, source)
	if err != nil {
		return fcbreak.ClientCommonConf{}, err
	}

	s, err := f.GetSection("common")
	if err != nil {
		return fcbreak.ClientCommonConf{}, fmt.Errorf("invalid configuration file, not found [common] section")
	}

	common := fcbreak.GetDefaultClientConf()
	err = s.MapTo(&common)
	if err != nil {
		return fcbreak.ClientCommonConf{}, err
	}
	return common, nil
}

func UnmarshalFromIni(section *ini.Section) (fcbreak.ServiceConf, error) {
	cfg := fcbreak.GetDefaultServiceConf()
	err := section.MapTo(&cfg)
	if err != nil {
		return cfg, err
	}
	cfg.Name = section.Name()
	return cfg, nil
}

func LoadAllProxyConfsFromIni(source interface{}) (map[string]fcbreak.ServiceConf, error) {
	f, err := ini.LoadSources(ini.LoadOptions{
		Insensitive:         false,
		InsensitiveSections: false,
		InsensitiveKeys:     false,
		IgnoreInlineComment: true,
		AllowBooleanKeys:    true,
	}, source)
	if err != nil {
		return nil, err
	}
	proxyConfs := make(map[string]fcbreak.ServiceConf)

	for _, section := range f.Sections() {
		name := section.Name()
		if name == ini.DefaultSection || name == "common" || strings.HasPrefix(name, "range:") {
			continue
		}
		newConf, newErr := UnmarshalFromIni(section)
		if newErr != nil {
			return nil, fmt.Errorf("failed to parse proxy %s, err: %v", name, newErr)
		}
		proxyConfs[name] = newConf
	}
	return proxyConfs, nil
}
