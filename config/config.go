package config

import (
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

var (
	v = viper.GetViper()
)

func init() {
	v.SetConfigName("gost")
	v.AddConfigPath("/etc/gost/")
	v.AddConfigPath("$HOME/.gost/")
	v.AddConfigPath(".")
}

var (
	global    = &Config{}
	globalMux sync.RWMutex
)

func Global() *Config {
	globalMux.RLock()
	defer globalMux.RUnlock()

	cfg := &Config{}
	*cfg = *global
	return cfg
}

func SetGlobal(c *Config) {
	globalMux.Lock()
	defer globalMux.Unlock()

	global = c
}

type LogConfig struct {
	Output string `yaml:",omitempty" json:"output,omitempty"`
	Level  string `yaml:",omitempty" json:"level,omitempty"`
	Format string `yaml:",omitempty" json:"format,omitempty"`
}

type ProfilingConfig struct {
	Addr string `json:"addr"`
}

type APIConfig struct {
	Addr       string      `json:"addr"`
	PathPrefix string      `yaml:"pathPrefix,omitempty" json:"pathPrefix,omitempty"`
	AccessLog  bool        `yaml:"accesslog,omitempty" json:"accesslog,omitempty"`
	Auth       *AuthConfig `yaml:",omitempty" json:"auth,omitempty"`
	Auther     string      `yaml:",omitempty" json:"auther,omitempty"`
}

type MetricsConfig struct {
	Addr string `json:"addr"`
	Path string `yaml:",omitempty" json:"path,omitempty"`
}

type TLSConfig struct {
	CertFile   string `yaml:"certFile,omitempty" json:"certFile,omitempty"`
	KeyFile    string `yaml:"keyFile,omitempty" json:"keyFile,omitempty"`
	CAFile     string `yaml:"caFile,omitempty" json:"caFile,omitempty"`
	Secure     bool   `yaml:",omitempty" json:"secure,omitempty"`
	ServerName string `yaml:"serverName,omitempty" json:"serverName,omitempty"`

	// for auto-generated default certificate.
	Validity     time.Duration `yaml:",omitempty" json:"validity,omitempty"`
	CommonName   string        `yaml:"commonName,omitempty" json:"commonName,omitempty"`
	Organization string        `yaml:",omitempty" json:"organization,omitempty"`
}

type AutherConfig struct {
	Name   string        `json:"name"`
	Auths  []*AuthConfig `yaml:",omitempty" json:"auths"`
	Reload time.Duration `yaml:",omitempty" json:"reload,omitempty"`
	File   *FileLoader   `yaml:",omitempty" json:"file,omitempty"`
	Redis  *RedisLoader  `yaml:",omitempty" json:"redis,omitempty"`
	HTTP   *HTTPLoader   `yaml:"http,omitempty" json:"http,omitempty"`
}

type AuthConfig struct {
	Username string `json:"username"`
	Password string `yaml:",omitempty" json:"password,omitempty"`
}

type SelectorConfig struct {
	Strategy    string        `json:"strategy"`
	MaxFails    int           `yaml:"maxFails" json:"maxFails"`
	FailTimeout time.Duration `yaml:"failTimeout" json:"failTimeout"`
}

type AdmissionConfig struct {
	Name string `json:"name"`
	// DEPRECATED by whitelist since beta.4
	Reverse   bool          `yaml:",omitempty" json:"reverse,omitempty"`
	Whitelist bool          `yaml:",omitempty" json:"whitelist,omitempty"`
	Matchers  []string      `json:"matchers"`
	Reload    time.Duration `yaml:",omitempty" json:"reload,omitempty"`
	File      *FileLoader   `yaml:",omitempty" json:"file,omitempty"`
	Redis     *RedisLoader  `yaml:",omitempty" json:"redis,omitempty"`
	HTTP      *HTTPLoader   `yaml:"http,omitempty" json:"http,omitempty"`
}

type BypassConfig struct {
	Name string `json:"name"`
	// DEPRECATED by whitelist since beta.4
	Reverse   bool          `yaml:",omitempty" json:"reverse,omitempty"`
	Whitelist bool          `yaml:",omitempty" json:"whitelist,omitempty"`
	Matchers  []string      `json:"matchers"`
	Reload    time.Duration `yaml:",omitempty" json:"reload,omitempty"`
	File      *FileLoader   `yaml:",omitempty" json:"file,omitempty"`
	Redis     *RedisLoader  `yaml:",omitempty" json:"redis,omitempty"`
	HTTP      *HTTPLoader   `yaml:"http,omitempty" json:"http,omitempty"`
}

type FileLoader struct {
	Path string `json:"path"`
}

type RedisLoader struct {
	Addr     string `json:"addr"`
	DB       int    `yaml:",omitempty" json:"db,omitempty"`
	Password string `yaml:",omitempty" json:"password,omitempty"`
	Key      string `yaml:",omitempty" json:"key,omitempty"`
	Type     string `yaml:",omitempty" json:"type,omitempty"`
}

type HTTPLoader struct {
	URL     string        `yaml:"url" json:"url"`
	Timeout time.Duration `yaml:",omitempty" json:"timeout,omitempty"`
}

type NameserverConfig struct {
	Addr     string        `json:"addr"`
	Chain    string        `yaml:",omitempty" json:"chain,omitempty"`
	Prefer   string        `yaml:",omitempty" json:"prefer,omitempty"`
	ClientIP string        `yaml:"clientIP,omitempty" json:"clientIP,omitempty"`
	Hostname string        `yaml:",omitempty" json:"hostname,omitempty"`
	TTL      time.Duration `yaml:",omitempty" json:"ttl,omitempty"`
	Timeout  time.Duration `yaml:",omitempty" json:"timeout,omitempty"`
}

type ResolverConfig struct {
	Name        string              `json:"name"`
	Nameservers []*NameserverConfig `json:"nameservers"`
}

type HostMappingConfig struct {
	IP       string   `json:"ip"`
	Hostname string   `json:"hostname"`
	Aliases  []string `yaml:",omitempty" json:"aliases,omitempty"`
}

type HostsConfig struct {
	Name     string               `json:"name"`
	Mappings []*HostMappingConfig `json:"mappings"`
	Reload   time.Duration        `yaml:",omitempty" json:"reload,omitempty"`
	File     *FileLoader          `yaml:",omitempty" json:"file,omitempty"`
	Redis    *RedisLoader         `yaml:",omitempty" json:"redis,omitempty"`
	HTTP     *HTTPLoader          `yaml:"http,omitempty" json:"http,omitempty"`
}

type RecorderConfig struct {
	Name  string         `json:"name"`
	File  *FileRecorder  `yaml:",omitempty" json:"file,omitempty"`
	Redis *RedisRecorder `yaml:",omitempty" json:"redis,omitempty"`
}

type FileRecorder struct {
	Path string `json:"path"`
	Sep  string `yaml:",omitempty" json:"sep,omitempty"`
}

type RedisRecorder struct {
	Addr     string `json:"addr"`
	DB       int    `yaml:",omitempty" json:"db,omitempty"`
	Password string `yaml:",omitempty" json:"password,omitempty"`
	Key      string `yaml:",omitempty" json:"key,omitempty"`
	Type     string `yaml:",omitempty" json:"type,omitempty"`
}

type RecorderObject struct {
	Name   string `json:"name"`
	Record string `json:"record"`
}

type LimiterConfig struct {
	Name   string        `json:"name"`
	Limits []string      `yaml:",omitempty" json:"limits,omitempty"`
	Reload time.Duration `yaml:",omitempty" json:"reload,omitempty"`
	File   *FileLoader   `yaml:",omitempty" json:"file,omitempty"`
	Redis  *RedisLoader  `yaml:",omitempty" json:"redis,omitempty"`
	HTTP   *HTTPLoader   `yaml:"http,omitempty" json:"http,omitempty"`
}

type ListenerConfig struct {
	Type       string            `json:"type"`
	Chain      string            `yaml:",omitempty" json:"chain,omitempty"`
	ChainGroup *ChainGroupConfig `yaml:"chainGroup,omitempty" json:"chainGroup,omitempty"`
	Auther     string            `yaml:",omitempty" json:"auther,omitempty"`
	Authers    []string          `yaml:",omitempty" json:"authers,omitempty"`
	Auth       *AuthConfig       `yaml:",omitempty" json:"auth,omitempty"`
	TLS        *TLSConfig        `yaml:",omitempty" json:"tls,omitempty"`
	Metadata   map[string]any    `yaml:",omitempty" json:"metadata,omitempty"`
}

type HandlerConfig struct {
	Type       string            `json:"type"`
	Retries    int               `yaml:",omitempty" json:"retries,omitempty"`
	Chain      string            `yaml:",omitempty" json:"chain,omitempty"`
	ChainGroup *ChainGroupConfig `yaml:"chainGroup,omitempty" json:"chainGroup,omitempty"`
	Auther     string            `yaml:",omitempty" json:"auther,omitempty"`
	Authers    []string          `yaml:",omitempty" json:"authers,omitempty"`
	Auth       *AuthConfig       `yaml:",omitempty" json:"auth,omitempty"`
	TLS        *TLSConfig        `yaml:",omitempty" json:"tls,omitempty"`
	Metadata   map[string]any    `yaml:",omitempty" json:"metadata,omitempty"`
}

type ForwarderConfig struct {
	Name     string               `yaml:",omitempty" json:"name,omitempty"`
	Selector *SelectorConfig      `yaml:",omitempty" json:"selector,omitempty"`
	Nodes    []*ForwardNodeConfig `json:"nodes"`
	// DEPRECATED by nodes since beta.4
	Targets []string `yaml:",omitempty" json:"targets,omitempty"`
}

type ForwardNodeConfig struct {
	Name     string   `yaml:",omitempty" json:"name,omitempty"`
	Addr     string   `yaml:",omitempty" json:"addr,omitempty"`
	Bypass   string   `yaml:",omitempty" json:"bypass,omitempty"`
	Bypasses []string `yaml:",omitempty" json:"bypasses,omitempty"`
}

type DialerConfig struct {
	Type     string         `json:"type"`
	Auth     *AuthConfig    `yaml:",omitempty" json:"auth,omitempty"`
	TLS      *TLSConfig     `yaml:",omitempty" json:"tls,omitempty"`
	Metadata map[string]any `yaml:",omitempty" json:"metadata,omitempty"`
}

type ConnectorConfig struct {
	Type     string         `json:"type"`
	Auth     *AuthConfig    `yaml:",omitempty" json:"auth,omitempty"`
	TLS      *TLSConfig     `yaml:",omitempty" json:"tls,omitempty"`
	Metadata map[string]any `yaml:",omitempty" json:"metadata,omitempty"`
}

type SockOptsConfig struct {
	Mark int `yaml:",omitempty" json:"mark,omitempty"`
}

type ServiceConfig struct {
	Name string `json:"name"`
	Addr string `yaml:",omitempty" json:"addr,omitempty"`
	// DEPRECATED by metadata.interface since beta.5
	Interface string `yaml:",omitempty" json:"interface,omitempty"`
	// DEPRECATED by metadata.so_mark since beta.5
	SockOpts   *SockOptsConfig   `yaml:"sockopts,omitempty" json:"sockopts,omitempty"`
	// // STUN
	// Stun       string            `yaml:",omitempty" json:"stun,omitempty"`
	// StunOnly   bool              `yaml:",omitempty" json:"stunonly,omitempty"`
	// NFQ        bool              `yaml:",omitempty" json:"nfq,omitempty"`
	// NFQID      string            `yaml:",omitempty" json:"nfqid,omitempty"`
	// SrcMAC     string            `yaml:",omitempty" json:"srcmac,omitempty"`
	// DstMAC     string            `yaml:",omitempty" json:"dstmac,omitempty"`
	// //
	Admission  string            `yaml:",omitempty" json:"admission,omitempty"`
	Admissions []string          `yaml:",omitempty" json:"admissions,omitempty"`
	Bypass     string            `yaml:",omitempty" json:"bypass,omitempty"`
	Bypasses   []string          `yaml:",omitempty" json:"bypasses,omitempty"`
	Resolver   string            `yaml:",omitempty" json:"resolver,omitempty"`
	Hosts      string            `yaml:",omitempty" json:"hosts,omitempty"`
	Limiter    string            `yaml:",omitempty" json:"limiter,omitempty"`
	CLimiter   string            `yaml:"climiter,omitempty" json:"climiter,omitempty"`
	RLimiter   string            `yaml:"rlimiter,omitempty" json:"rlimiter,omitempty"`
	Recorders  []*RecorderObject `yaml:",omitempty" json:"recorders,omitempty"`
	Handler    *HandlerConfig    `yaml:",omitempty" json:"handler,omitempty"`
	Listener   *ListenerConfig   `yaml:",omitempty" json:"listener,omitempty"`
	Forwarder  *ForwarderConfig  `yaml:",omitempty" json:"forwarder,omitempty"`
	Metadata   map[string]any    `yaml:",omitempty" json:"metadata,omitempty"`
}

type ChainConfig struct {
	Name string `json:"name"`
	// REMOVED since beta.6
	// Selector *SelectorConfig `yaml:",omitempty" json:"selector,omitempty"`
	Hops     []*HopConfig   `json:"hops"`
	Metadata map[string]any `yaml:",omitempty" json:"metadata,omitempty"`
}

type ChainGroupConfig struct {
	Chains   []string        `yaml:",omitempty" json:"chains,omitempty"`
	Selector *SelectorConfig `yaml:",omitempty" json:"selector,omitempty"`
}

type HopConfig struct {
	Name      string          `json:"name"`
	Interface string          `yaml:",omitempty" json:"interface,omitempty"`
	SockOpts  *SockOptsConfig `yaml:"sockopts,omitempty" json:"sockopts,omitempty"`
	Selector  *SelectorConfig `yaml:",omitempty" json:"selector,omitempty"`
	Bypass    string          `yaml:",omitempty" json:"bypass,omitempty"`
	Bypasses  []string        `yaml:",omitempty" json:"bypasses,omitempty"`
	Resolver  string          `yaml:",omitempty" json:"resolver,omitempty"`
	Hosts     string          `yaml:",omitempty" json:"hosts,omitempty"`
	Nodes     []*NodeConfig   `yaml:",omitempty" json:"nodes,omitempty"`
}

type NodeConfig struct {
	Name      string           `json:"name"`
	Addr      string           `yaml:",omitempty" json:"addr,omitempty"`
	Interface string           `yaml:",omitempty" json:"interface,omitempty"`
	SockOpts  *SockOptsConfig  `yaml:"sockopts,omitempty" json:"sockopts,omitempty"`
	Bypass    string           `yaml:",omitempty" json:"bypass,omitempty"`
	Bypasses  []string         `yaml:",omitempty" json:"bypasses,omitempty"`
	Resolver  string           `yaml:",omitempty" json:"resolver,omitempty"`
	Hosts     string           `yaml:",omitempty" json:"hosts,omitempty"`
	Connector *ConnectorConfig `yaml:",omitempty" json:"connector,omitempty"`
	Dialer    *DialerConfig    `yaml:",omitempty" json:"dialer,omitempty"`
	Metadata  map[string]any   `yaml:",omitempty" json:"metadata,omitempty"`
}

type Config struct {
	Services   []*ServiceConfig   `json:"services"`
	Chains     []*ChainConfig     `yaml:",omitempty" json:"chains,omitempty"`
	Hops       []*HopConfig       `yaml:",omitempty" json:"hops,omitempty"`
	Authers    []*AutherConfig    `yaml:",omitempty" json:"authers,omitempty"`
	Admissions []*AdmissionConfig `yaml:",omitempty" json:"admissions,omitempty"`
	Bypasses   []*BypassConfig    `yaml:",omitempty" json:"bypasses,omitempty"`
	Resolvers  []*ResolverConfig  `yaml:",omitempty" json:"resolvers,omitempty"`
	Hosts      []*HostsConfig     `yaml:",omitempty" json:"hosts,omitempty"`
	Recorders  []*RecorderConfig  `yaml:",omitempty" json:"recorders,omitempty"`
	Limiters   []*LimiterConfig   `yaml:",omitempty" json:"limiters,omitempty"`
	CLimiters  []*LimiterConfig   `yaml:"climiters,omitempty" json:"climiters,omitempty"`
	RLimiters  []*LimiterConfig   `yaml:"rlimiters,omitempty" json:"rlimiters,omitempty"`
	TLS        *TLSConfig         `yaml:",omitempty" json:"tls,omitempty"`
	Log        *LogConfig         `yaml:",omitempty" json:"log,omitempty"`
	Profiling  *ProfilingConfig   `yaml:",omitempty" json:"profiling,omitempty"`
	API        *APIConfig         `yaml:",omitempty" json:"api,omitempty"`
	Metrics    *MetricsConfig     `yaml:",omitempty" json:"metrics,omitempty"`
}

func (c *Config) Load() error {
	if err := v.ReadInConfig(); err != nil {
		return err
	}

	return v.Unmarshal(c)
}

func (c *Config) Read(r io.Reader) error {
	if err := v.ReadConfig(r); err != nil {
		return err
	}

	return v.Unmarshal(c)
}

func (c *Config) ReadFile(file string) error {
	v.SetConfigFile(file)
	if err := v.ReadInConfig(); err != nil {
		return err
	}
	return v.Unmarshal(c)
}

func (c *Config) Write(w io.Writer, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(c)
		return nil
	case "yaml":
		fallthrough
	default:
		enc := yaml.NewEncoder(w)
		defer enc.Close()

		return enc.Encode(c)
	}
}
