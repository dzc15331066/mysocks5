package mysocks5

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

const (
	socks5Version = uint8(5)
	noAuth        = uint8(0)
)

// Config is used to setup and configure a Server
type Config struct {
	// BindIP is used for bind or udp associate
	BindIP net.IP
	Logger *log.Logger
}

// Server is responsible for accepting connections and handling
// the details of the SOCKS5 protocol
type Server struct {
	config *Config
}

// New creates a new Server and potentially returns an error
func New(conf *Config) (*Server, error) {
	if conf.Logger == nil {
		conf.Logger = log.New(os.Stdout, "", log.LstdFlags)
	}
	server := &Server{
		config: conf,
	}
	return server, nil
}

// ListenAndServe is used to create a listener and serve on it
func (s *Server) ListenAndServe(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	fmt.Printf("listening to %v\n", addr)
	return s.Serve(l)
}

// Serve is used to serve connections from a listener
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.ServeConn(conn)
	}
}

// ServeConn is used to serve a single connection.
func (s *Server) ServeConn(conn net.Conn) error {
	defer conn.Close()
	bufConn := bufio.NewReader(conn)

	// Read the version byte
	version := []byte{0}
	if _, err := bufConn.Read(version); err != nil {
		s.config.Logger.Printf("[ERR] socks: Failed to get version byte: %v", err)
		return err
	}
	// Ensure we are compatible
	if version[0] != socks5Version {
		err := fmt.Errorf("Unsupported SOCKS version: %v", version)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		return err
	}
	if err := s.needNoAuth(bufConn, conn); err != nil {
		s.config.Logger.Printf("[ERR] socks: Invalid method region: %v", err)
		return err
	}
	request, err := NewRequest(bufConn)
	if err != nil {
		if err == unrecognizedAddrType {
			if err := sendReply(conn, addrTypeNotSupported, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
		}
		return fmt.Errorf("Failed to read destination address: %v", err)
	}
	if client, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		request.RemoteAddr = &AddrSpec{IP: client.IP, Port: client.Port}
	}
	// Process the client request
	if err := s.handleRequest(request, conn); err != nil {
		err = fmt.Errorf("Failed to handle request: %v", err)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		return err
	}
	return nil
}

// 告诉客户端我们采用无认证的方式连接
func (s *Server) needNoAuth(r io.Reader, w io.Writer) error {
	header := []byte{0}
	if _, err := r.Read(header); err != nil {
		return err
	}
	numMethods := int(header[0])
	methods := make([]byte, numMethods)
	if _, err := io.ReadAtLeast(r, methods, numMethods); err != nil {
		return err
	}
	_, err := w.Write([]byte{socks5Version, noAuth})
	return err
}
