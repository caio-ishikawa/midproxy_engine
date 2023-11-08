package midproxy_engine

import (
	"bufio"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/patrickmn/go-cache"
)

const (
	ROOT_CA_CERT_PATH = "./root.crt"
	ROOT_CA_KEY_PATH  = "./root.key"
	MITM_PORT         = ":9900"
	MITM_URL          = "localhost:9900"
	HTTP_MITM_URL     = "http://localhost:9900"
)

// ProxyConfig represents the static settigs for the proxy server.
type ProxyConfig struct {
	caCert       *x509.Certificate
	caPrivateKey *rsa.PrivateKey
	organization string
	port         string
	debug        bool
}

// Proxy represents the proxy server.
type Proxy struct {
	listener   net.Listener
	mitmServer *http.Server
	config     ProxyConfig
	OnReq      func(w http.ResponseWriter, r *http.Request)
	LogChan    chan string
	ErrChan    chan string
	certCache  *cache.Cache
}

// Starts http listener and listens to incoming requests for http.MethodConnect
func (p *Proxy) StartProxy() {
	p.logDebug("Starting listener in port 9090", nil)

	for {
		clientConn, err := p.listener.Accept()
		if err != nil {
			p.logDebug("Error accepting connection", err)
			continue
		}

		req, err := http.ReadRequest(bufio.NewReader(clientConn))
		if err != nil {
			p.logErr("Could not read request from client", err)
			continue
		}

		_, port, err := net.SplitHostPort(req.Host)
		if err != nil {
			port = ""
		}

		if req.Method == http.MethodConnect && port == "443" {
			p.logDebug("Received CONNECT request", nil)
			go p.handleConnect(req, clientConn)
			// WARN: not sure how reliable this is
		} else if req.Method != http.MethodConnect && port != "443" {
			p.logDebug("Starting HTTP handler", nil)
			go p.handleHTTP(req, clientConn)
		} else {
			p.logErr("Could not parse request", fmt.Errorf("Invalid request: %s", req.Method))
		}
	}
}

// logeErr writes error log message to ErrChan to be handled externally.
func (p *Proxy) logErr(msg string, err error) {
	p.ErrChan <- fmt.Sprintf("%s: %d", msg, err)
}

// logMsg writes to channel to be handled externally.
func (p *Proxy) logDebug(msg string, err error) {
	if p.config.debug {
		if err != nil {
			p.LogChan <- fmt.Sprintf("Error: %s. %d", msg, err)
			return
		}
		p.LogChan <- msg
	}
}

// handleConnect starts MITM server with a dynamically generated TLS config, and establishes a TLS tunnel between the client and the MITM server.
func (p *Proxy) handleConnect(req *http.Request, clientConn net.Conn) {
	tlsConfig := p.GenerateTLSConfig(req.Host)

	if p.mitmServer == nil {
		go p.startMITMServer(tlsConfig)
	}

	subConn, err := net.Dial("tcp", MITM_URL)
	if err != nil {
		p.logDebug("Could not dial MITM server", err)
		clientConn.Close()
		p.StartProxy() // TODO: Not sure if this is a good idea
	}

	clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

	p.handleRequest(clientConn, subConn)
}

// handleHTTP performs the onReq method using a wrapper struct that implements http.ResponseWriter.
func (p *Proxy) handleHTTP(req *http.Request, clientConn net.Conn) {
	defer clientConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

	w := ProxyResponseWriter{header: http.Header{}}
	p.setRequestURL("http", req)
	p.OnReq(&w, req)

	body := w.GetContent()

	// writing headers
	for key, values := range w.header {
		for _, value := range values {
			_, err := clientConn.Write([]byte(fmt.Sprintf("%s: %s\r\n", key, value)))
			if err != nil {
				p.logDebug("Could not write header data to client", err)
				return
			}
		}
	}

	clientConn.Write([]byte(fmt.Sprintf("HTTP/1.1 %d\r\n", w.statusCode)))
	clientConn.Write(body)
}

// getFullURL populates URL field with absolute URL.
func (p *Proxy) setRequestURL(protocol string, req *http.Request) {
	if !req.URL.IsAbs() {
		absURL, err := url.Parse(fmt.Sprintf("%s://%s%s", protocol, req.Host, req.URL.String()))
		if err != nil {
			p.logDebug("Could not parse URL", err)
			return
		}
		p.logDebug(fmt.Sprintf("Request URL was changed from %s to %s", req.URL, absURL), nil)
		req.URL = absURL
	}
}

// startMITMServer spawns a simple MITM server using provided tls.Config object.
func (p *Proxy) startMITMServer(tlsConfig *tls.Config) {
	p.mitmServer = &http.Server{
		Addr: MITM_PORT,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p.setRequestURL("https", r)
			p.OnReq(w, r)
		}),
	}

	if tlsConfig != nil {
		p.logDebug("Starting TLS sub-server", nil)
		p.mitmServer.TLSConfig = tlsConfig

		if err := p.mitmServer.ListenAndServeTLS("", ""); err != nil {
			p.logErr("Could not start TLS MITM server", err)
		}
	} else {
		p.logDebug("Starting HTTP sub-server", nil)

		if err := p.mitmServer.ListenAndServe(); err != nil {
			p.logErr("Could not start MITM server", err)
		}
	}
}

// handleRequest starts the data transfer to/from clientConn to/from subcConn.
func (p *Proxy) handleRequest(clientConn, subConn net.Conn) {
	clientComplete := make(chan struct{})
	subComplete := make(chan struct{})

	go p.transferData(clientConn, subConn, clientComplete)
	go p.transferData(subConn, clientConn, subComplete)

	<-clientComplete
	<-subComplete
}

// transferData sequentially transfers data from src to dst.
// Effectively acts as a TLS tunnel between the src and dst.
func (p *Proxy) transferData(src, dst net.Conn, ch chan struct{}) {
	defer src.Close()
	defer close(ch)

	buf := make([]byte, 1024)
	for {
		n, err := src.Read(buf)
		if err != nil {
			p.logDebug("Could not read from source connection. Closing connections", err)
			break
		}

		_, err = dst.Write(buf[:n])
		if err != nil {
			p.logDebug("Could not write to destination connection. Closing connections", err)
			break
		}
	}
}

// Stop closes the client connection.
func (p *Proxy) Stop() {
	p.listener.Close()
}

// Generates new proxy configuration. Expects root cert and key to be in src folder.
// TODO: Add support for flag specifying location of cert and key files.
func NewProxy(
	debugMode bool,
	onReq func(w http.ResponseWriter, r *http.Request),
) (Proxy, error) {
	port := "9090"
	org := "IntruderProxy"

	cert, err := loadRootCert()
	if err != nil {
		return Proxy{}, fmt.Errorf("Could not load root CA certificate: %d", err)
	}

	key, err := loadRootKey()
	if err != nil {
		return Proxy{}, fmt.Errorf("Could not load CA private key: %d", err)
	}

	cache := cache.New(3*time.Minute, 5*time.Minute)

	config := ProxyConfig{
		caCert:       cert,
		caPrivateKey: key,
		organization: org,
		port:         port,
		debug:        debugMode,
	}

	p := Proxy{
		config:    config,
		OnReq:     onReq,
		LogChan:   make(chan string),
		ErrChan:   make(chan string),
		certCache: cache,
	}

	tlsCert, err := p.getOrCreateTLSCert(("127.0.0.1:") + port)
	if err != nil {
		return Proxy{}, fmt.Errorf("Could not generate TLS cert for proxy: %d", err)
	}

	tlsConfig := tls.Config{
		Certificates:       []tls.Certificate{*tlsCert},
		InsecureSkipVerify: true,
	}

	listener, err := tls.Listen("tcp", ("localhost:" + port), &tlsConfig)
	if err != nil {
		return Proxy{}, fmt.Errorf("Could not start TLS listener: %d", err)
	}

	p.listener = listener
	return p, nil
}
