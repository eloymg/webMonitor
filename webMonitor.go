package main

import (
	"github.com/eloymg/hit"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"index/suffixarray"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/smtp"
	"os"
	"time"
)

var seconds = flag.Int("s", 600, "Define max loop seconds")
var reset = flag.Bool("r", false, "Set true to reset signs")
var domainList = flag.String("f", "", "Define list of urls")
var patternList = flag.String("p", "", "Define list of patterns")
var userAgentList = flag.String("a", "", "Define list of user agents")






func main() {

	flag.Parse()

	c := Config{
		*seconds,
		*reset,
		*domainList,
		*patterList,
		*userAgentList
	}

	if c.domainList == "" {
		fmt.Println("Define a domain list path with flag -f")
		os.Exit(1)
	}
	if c.patterList == "" {
		fmt.Println("Define a pattern list path with flag -p")
		os.Exit(1)
	}
	if c.seconds == 600 {
		fmt.Println("Using default max loop seconds {", *seconds, "}\nUse -s for define custom max bucle seconds\n")
	}
	if c.seconds == 0 {
		*seconds = *seconds + 5
	}
	if c.reset {
		os.Remove("signatures")
	}
	h := Hit{c}
	h.start()

	
}










