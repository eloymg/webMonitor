package main

import (
	"github.com/eloymg/webMonitor/hit"
	"flag"
	"fmt"
	"os"
)

var Seconds = flag.Int("s", 600, "Define max loop Seconds")
var Reset = flag.Bool("r", false, "Set true to Reset signs")
var DomainList = flag.String("f", "", "Define list of urls")
var PatternList = flag.String("p", "", "Define list of patterns")
var UserAgentList = flag.String("a", "", "Define list of user agents")


func main() {

	flag.Parse()
	
	h := hit.Hit{}

	h.Config.DomainList = *DomainList
	h.Config.PatternList = *PatternList
	h.Config.Seconds = *Seconds
	h.Config.Reset = *Reset

	if h.Config.DomainList == "" {
		fmt.Println("Define a domain list path with flag -f")
		os.Exit(1)
	}
	if h.Config.PatternList == "" {
		fmt.Println("Define a pattern list path with flag -p")
		os.Exit(1)
	}
	if h.Config.Seconds == 600 {
		fmt.Println("Using default max loop Seconds {", *Seconds, "}\nUse -s for define custom max bucle Seconds\n")
	}
	if h.Config.Seconds == 0 {
		*Seconds = *Seconds + 5
	}
	if h.Config.Reset {
		os.Remove("signatures")
	}

	h.Start()
	h.GoHits()

	
}










