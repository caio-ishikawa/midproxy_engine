package midproxy_engine

import (
	"net/http"
)

// Struct wrapping around ResponseWriter allowing HTTP servers to run the user-defined handler without
// spawning  a new server
type ProxyResponseWriter struct {
	content    []byte
	statusCode int
	header     http.Header
}

func (w *ProxyResponseWriter) Header() http.Header {
	return w.header
}

// Made for single Write
func (w *ProxyResponseWriter) Write(b []byte) (int, error) {
	w.content = b
	return len(b), nil
}

func (w *ProxyResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}

func (w ProxyResponseWriter) GetContent() []byte {
	return w.content
}
