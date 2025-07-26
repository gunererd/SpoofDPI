package util

import (
	"fmt"
	"regexp"

	"github.com/pterm/pterm"
	"github.com/pterm/pterm/putils"
)

type Config struct {
	Addr                string
	Port                int
	DnsAddr             string
	DnsPort             int
	DnsIPv4Only         bool
	EnableDoh           bool
	Debug               bool
	Silent              bool
	SystemProxy         bool
	Timeout             int
	WindowSize          int
	AllowedPatterns     []*regexp.Regexp
	TimingRandomization bool
	TimingDelayMin      uint16
	TimingDelayMax      uint16
}

var config *Config

func GetConfig() *Config {
	if config == nil {
		config = new(Config)
	}
	return config
}

func (c *Config) Load(args *Args) {
	c.Addr = args.Addr
	c.Port = int(args.Port)
	c.DnsAddr = args.DnsAddr
	c.DnsPort = int(args.DnsPort)
	c.DnsIPv4Only = args.DnsIPv4Only
	c.Debug = args.Debug
	c.EnableDoh = args.EnableDoh
	c.Silent = args.Silent
	c.SystemProxy = args.SystemProxy
	c.Timeout = int(args.Timeout)
	c.AllowedPatterns = parseAllowedPattern(args.AllowedPattern)
	c.WindowSize = int(args.WindowSize)
	// Handle random timing argument
	if args.RandomTiming.IsSet {
		c.TimingRandomization = true
		// Convert timing delay preset to min/max values
		preset := args.RandomTiming.Value
		if preset == "" {
			preset = "short" // Default when flag is used without value
		}
		switch preset {
		case "short":
			c.TimingDelayMin = 5
			c.TimingDelayMax = 25
		case "medium":
			c.TimingDelayMin = 25
			c.TimingDelayMax = 50
		case "long":
			c.TimingDelayMin = 50
			c.TimingDelayMax = 100
		default:
			// Default to short for invalid values
			c.TimingDelayMin = 5
			c.TimingDelayMax = 25
		}
	} else {
		c.TimingRandomization = false
		c.TimingDelayMin = 0
		c.TimingDelayMax = 0
	}
}

func parseAllowedPattern(patterns StringArray) []*regexp.Regexp {
	var allowedPatterns []*regexp.Regexp

	for _, pattern := range patterns {
		allowedPatterns = append(allowedPatterns, regexp.MustCompile(pattern))
	}

	return allowedPatterns
}

func PrintColoredBanner() {
	cyan := putils.LettersFromStringWithStyle("Spoof", pterm.NewStyle(pterm.FgCyan))
	purple := putils.LettersFromStringWithStyle("DPI", pterm.NewStyle(pterm.FgLightMagenta))
	pterm.DefaultBigText.WithLetters(cyan, purple).Render()

	pterm.DefaultBulletList.WithItems([]pterm.BulletListItem{
		{Level: 0, Text: "ADDR    : " + fmt.Sprint(config.Addr)},
		{Level: 0, Text: "PORT    : " + fmt.Sprint(config.Port)},
		{Level: 0, Text: "DNS     : " + fmt.Sprint(config.DnsAddr)},
		{Level: 0, Text: "DEBUG   : " + fmt.Sprint(config.Debug)},
	}).Render()

	pterm.DefaultBasicText.Println("Press 'CTRL + c' to quit")
}
