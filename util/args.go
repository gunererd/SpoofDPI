package util

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"
)

type Args struct {
	Addr           string
	Port           uint16
	DnsAddr        string
	DnsPort        uint16
	DnsIPv4Only    bool
	EnableDoh      bool
	Debug          bool
	Silent         bool
	SystemProxy    bool
	Timeout        uint16
	AllowedPattern StringArray
	WindowSize     uint16
	Version        bool
	RandomTiming TimingFlag
}

type StringArray []string

func (arr *StringArray) String() string {
	return fmt.Sprintf("%s", *arr)
}

func (arr *StringArray) Set(value string) error {
	*arr = append(*arr, value)
	return nil
}

type TimingFlag struct {
	Value string
	IsSet bool
}

func (t *TimingFlag) String() string {
	return t.Value
}

func (t *TimingFlag) Set(value string) error {
	t.Value = value
	t.IsSet = true
	return nil
}


func ParseArgs() *Args {
	args := new(Args)

	flag.StringVar(&args.Addr, "addr", "127.0.0.1", "listen address")
	uintNVar(&args.Port, "port", 8080, "port")
	flag.StringVar(&args.DnsAddr, "dns-addr", "8.8.8.8", "dns address")
	uintNVar(&args.DnsPort, "dns-port", 53, "port number for dns")
	flag.BoolVar(&args.EnableDoh, "enable-doh", false, "enable 'dns-over-https'")
	flag.BoolVar(&args.Debug, "debug", false, "enable debug output")
	flag.BoolVar(&args.Silent, "silent", false, "do not show the banner and server information at start up")
	flag.BoolVar(&args.SystemProxy, "system-proxy", true, "enable system-wide proxy")
	uintNVar(&args.Timeout, "timeout", 0, "timeout in milliseconds; no timeout when not given")
	uintNVar(&args.WindowSize, "window-size", 0, `chunk size, in number of bytes, for fragmented client hello,
try lower values if the default value doesn't bypass the DPI;
when not given, the client hello packet will be sent in two parts:
fragmentation for the first data packet and the rest
`)
	flag.BoolVar(&args.Version, "v", false, "print spoofdpi's version; this may contain some other relevant information")
	flag.Var(
		&args.AllowedPattern,
		"pattern",
		"bypass DPI only on packets matching this regex pattern; can be given multiple times",
	)
	flag.BoolVar(&args.DnsIPv4Only, "dns-ipv4-only", false, "resolve only version 4 addresses")
	flag.Var(&args.RandomTiming, "random-timing", "enable random timing delays: short, medium, long (defaults to short)")

	flag.Parse()
	
	// Handle --random-timing without value (set default to "short")
	for i, arg := range os.Args {
		if arg == "--random-timing" || arg == "-random-timing" {
			// Check if next arg exists and is not a flag
			if i+1 >= len(os.Args) || strings.HasPrefix(os.Args[i+1], "-") {
				args.RandomTiming.Value = "short"
				args.RandomTiming.IsSet = true
			}
			break
		}
	}

	return args
}

var (
	errParse = errors.New("parse error")
	errRange = errors.New("value out of range")
)

type unsigned interface {
	~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

func uintNVar[T unsigned](p *T, name string, value T, usage string) {
	flag.CommandLine.Var(newUintNValue(value, p), name, usage)
}

type uintNValue[T unsigned] struct {
	val *T
}

func newUintNValue[T unsigned](val T, p *T) *uintNValue[T] {
	*p = val
	return &uintNValue[T]{val: p}
}

func (u *uintNValue[T]) Set(s string) error {
	size := int(unsafe.Sizeof(*u.val) * 8)
	v, err := strconv.ParseUint(s, 0, size)
	if err != nil {
		err = numError(err)
	}
	*u.val = T(v)
	return err
}

func (u *uintNValue[T]) Get() any {
	if u.val == nil {
		return T(0)
	}
	return *u.val
}

func (u *uintNValue[T]) String() string {
	if u.val == nil {
		return "0"
	}
	return strconv.FormatUint(uint64(*u.val), 10)
}

func numError(err error) error {
	if errors.Is(err, strconv.ErrSyntax) {
		return errParse
	}
	if errors.Is(err, strconv.ErrRange) {
		return errRange
	}
	return err
}
