package handler

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"regexp"
	"strconv"
	"time"

	"github.com/xvzc/SpoofDPI/packet"
	"github.com/xvzc/SpoofDPI/util"
	"github.com/xvzc/SpoofDPI/util/log"
)

// HttpsHandlerConfig contains configuration options for HTTPS handler
type HttpsHandlerConfig struct {
	// Core settings
	Timeout         int              // Connection timeout in milliseconds
	WindowSize      int              // Fragmentation window size
	AllowedPatterns []*regexp.Regexp // Regex patterns to bypass DPI
	Exploit         bool             // Enable DPI bypass exploit

	// Timing randomization settings
	TimingRandomization bool   // Enable timing randomization
	TimingDelayMin      uint16 // Minimum delay in milliseconds
	TimingDelayMax      uint16 // Maximum delay in milliseconds
}

// DefaultHttpsHandlerConfig returns default configuration
func DefaultHttpsHandlerConfig() HttpsHandlerConfig {
	return HttpsHandlerConfig{
		Timeout:             0,     // No timeout
		WindowSize:          0,     // Legacy fragmentation
		AllowedPatterns:     nil,   // No pattern filtering
		Exploit:             true,  // Enable DPI bypass
		TimingRandomization: false, // Disabled by default
		TimingDelayMin:      5,     // 5ms minimum
		TimingDelayMax:      50,    // 50ms maximum
	}
}

// Validate checks if the configuration is valid
func (c HttpsHandlerConfig) Validate() error {
	if c.Timeout < 0 {
		return errors.New("timeout cannot be negative")
	}

	if c.WindowSize < 0 {
		return errors.New("window size cannot be negative")
	}

	if c.TimingRandomization && c.TimingDelayMin > c.TimingDelayMax {
		return errors.New("timing delay min cannot be greater than max")
	}

	return nil
}

type HttpsHandler struct {
	bufferSize int
	protocol   string
	port       int
	config     HttpsHandlerConfig
}

// HttpsHandlerOption represents a configuration option for HTTPS handler
type HttpsHandlerOption func(*HttpsHandlerConfig)

// WithTimeout sets the connection timeout in milliseconds
func WithTimeout(timeout int) HttpsHandlerOption {
	return func(c *HttpsHandlerConfig) {
		c.Timeout = timeout
	}
}

// WithWindowSize sets the fragmentation window size
func WithWindowSize(size int) HttpsHandlerOption {
	return func(c *HttpsHandlerConfig) {
		c.WindowSize = size
	}
}

// WithAllowedPatterns sets the regex patterns for DPI bypass
func WithAllowedPatterns(patterns []*regexp.Regexp) HttpsHandlerOption {
	return func(c *HttpsHandlerConfig) {
		c.AllowedPatterns = patterns
	}
}

// WithExploit enables or disables DPI bypass exploit
func WithExploit(exploit bool) HttpsHandlerOption {
	return func(c *HttpsHandlerConfig) {
		c.Exploit = exploit
	}
}

// WithTimingRandomization enables timing randomization with min/max delays
func WithTimingRandomization(min, max uint16) HttpsHandlerOption {
	return func(c *HttpsHandlerConfig) {
		c.TimingRandomization = true
		c.TimingDelayMin = min
		c.TimingDelayMax = max
	}
}

// WithoutTimingRandomization disables timing randomization
func WithoutTimingRandomization() HttpsHandlerOption {
	return func(c *HttpsHandlerConfig) {
		c.TimingRandomization = false
	}
}

// NewHttpsHandler creates a new HTTPS handler with functional options
func NewHttpsHandler(opts ...HttpsHandlerOption) *HttpsHandler {
	// Start with default configuration
	config := DefaultHttpsHandlerConfig()

	// Apply all options
	for _, opt := range opts {
		opt(&config)
	}

	// Validate final configuration
	if err := config.Validate(); err != nil {
		// Use defaults if validation fails
		config = DefaultHttpsHandlerConfig()
	}

	return &HttpsHandler{
		bufferSize: 1024,
		protocol:   "HTTPS",
		port:       443,
		config:     config,
	}
}

func (h *HttpsHandler) randomDelay(ctx context.Context) {
	if !h.config.TimingRandomization {
		return
	}

	if h.config.TimingDelayMin >= h.config.TimingDelayMax {
		return
	}

	// Generate random delay between min and max
	delayRange := h.config.TimingDelayMax - h.config.TimingDelayMin
	delay := h.config.TimingDelayMin + uint16(rand.Intn(int(delayRange)+1))

	// logger := log.GetCtxLogger(ctx)
	// logger.Debug().Msgf("applying timing delay: %dms", delay)

	time.Sleep(time.Duration(delay) * time.Millisecond)
}

func (h *HttpsHandler) Serve(ctx context.Context, lConn *net.TCPConn, initPkt *packet.HttpRequest, ip string) {
	ctx = util.GetCtxWithScope(ctx, h.protocol)
	logger := log.GetCtxLogger(ctx)

	// Create a connection to the requested server
	var err error
	if initPkt.Port() != "" {
		h.port, err = strconv.Atoi(initPkt.Port())
		if err != nil {
			logger.Debug().Msgf("error parsing port for %s aborting..", initPkt.Domain())
		}
	}

	rConn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: net.ParseIP(ip), Port: h.port})
	if err != nil {
		lConn.Close()
		logger.Debug().Msgf("%s", err)
		return
	}

	logger.Debug().Msgf("new connection to the server %s -> %s", rConn.LocalAddr(), initPkt.Domain())

	_, err = lConn.Write([]byte(initPkt.Version() + " 200 Connection Established\r\n\r\n"))
	if err != nil {
		logger.Debug().Msgf("error sending 200 connection established to the client: %s", err)
		return
	}

	logger.Debug().Msgf("sent connection established to %s", lConn.RemoteAddr())

	// Read client hello
	m, err := packet.ReadTLSMessage(lConn)
	if err != nil || !m.IsClientHello() {
		logger.Debug().Msgf("error reading client hello from %s: %s", lConn.RemoteAddr().String(), err)
		return
	}
	clientHello := m.Raw

	logger.Debug().Msgf("client sent hello %d bytes", len(clientHello))

	// Generate a go routine that reads from the server
	go h.communicate(ctx, rConn, lConn, initPkt.Domain(), lConn.RemoteAddr().String())
	go h.communicate(ctx, lConn, rConn, lConn.RemoteAddr().String(), initPkt.Domain())

	if h.config.Exploit {
		logger.Debug().Msgf("writing chunked client hello to %s", initPkt.Domain())
		chunks := splitInChunks(ctx, clientHello, h.config.WindowSize)
		if _, err := h.writeChunks(ctx, rConn, chunks); err != nil {
			logger.Debug().Msgf("error writing chunked client hello to %s: %s", initPkt.Domain(), err)
			return
		}
	} else {
		logger.Debug().Msgf("writing plain client hello to %s", initPkt.Domain())
		if _, err := rConn.Write(clientHello); err != nil {
			logger.Debug().Msgf("error writing plain client hello to %s: %s", initPkt.Domain(), err)
			return
		}
	}
}

func (h *HttpsHandler) communicate(ctx context.Context, from *net.TCPConn, to *net.TCPConn, fd string, td string) {
	ctx = util.GetCtxWithScope(ctx, h.protocol)
	logger := log.GetCtxLogger(ctx)

	defer func() {
		from.Close()
		to.Close()

		logger.Debug().Msgf("closing proxy connection: %s -> %s", fd, td)
	}()

	buf := make([]byte, h.bufferSize)
	for {
		err := setConnectionTimeout(from, h.config.Timeout)
		if err != nil {
			logger.Debug().Msgf("error while setting connection deadline for %s: %s", fd, err)
		}

		bytesRead, err := ReadBytes(ctx, from, buf)
		if err != nil {
			logger.Debug().Msgf("error reading from %s: %s", fd, err)
			return
		}

		if _, err := to.Write(bytesRead); err != nil {
			logger.Debug().Msgf("error writing to %s", td)
			return
		}
	}
}

func splitInChunks(ctx context.Context, bytes []byte, size int) [][]byte {
	logger := log.GetCtxLogger(ctx)

	var chunks [][]byte
	var raw []byte = bytes

	logger.Debug().Msgf("window-size: %d", size)

	if size > 0 {
		for {
			if len(raw) == 0 {
				break
			}

			// necessary check to avoid slicing beyond
			// slice capacity
			if len(raw) < size {
				size = len(raw)
			}

			chunks = append(chunks, raw[0:size])
			raw = raw[size:]
		}

		return chunks
	}

	// When the given window-size <= 0

	if len(raw) < 1 {
		return [][]byte{raw}
	}

	logger.Debug().Msg("using legacy fragmentation")

	return [][]byte{raw[:1], raw[1:]}
}

func (h *HttpsHandler) writeChunks(ctx context.Context, conn *net.TCPConn, c [][]byte) (n int, err error) {
	total := 0
	for i := 0; i < len(c); i++ {
		// Add delay before writing chunk (except first chunk)
		if i > 0 {
			h.randomDelay(ctx)
		}

		b, err := conn.Write(c[i])
		if err != nil {
			return 0, err
		}

		total += b
	}

	return total, nil
}
