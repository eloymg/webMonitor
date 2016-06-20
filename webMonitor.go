package main

import (
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
	"strings"
	"time"
)

var seconds = flag.Int("s", 600, "Define max loop time (s)")
var reset = flag.Bool("r", false, "Set true to reset signatures")
var dom_list = flag.String("f", "", "Define list of urls")
var patr_list = flag.String("p", "", "Define list of patterns")
var useragent_list = flag.String("a", "", "Define list of user agents")

func main() {

	flag.Parse()

	if *dom_list == "" {
		fmt.Print("Define a domain list path with flag -f")
		os.Exit(1)
	}
	if *patr_list == "" {
		fmt.Print("Define a pattern list path with flag -p")
		os.Exit(1)
	}
	if *seconds == 600 {
		fmt.Print("Using default max loop time {", *seconds, "s}\nUse -s for define custom max loop time (s)\n")
	}
	if *seconds == 0 {
		*seconds = *seconds + 1
	}
	if *reset {
		os.Remove("signatures")
	}
	var array_useragents = []string{}
	if *useragent_list == "" {

		array_useragents = []string{"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
			"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/601.6.17 (KHTML, like Gecko) Version/9.1.1 Safari/601.6.17",
			"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0",
			"Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L Build/IML74K) AppleWebkit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30"}
		fmt.Println("Using default list of user agents (use -a for define a list)")

	} else {
		content2, err := ioutil.ReadFile(*useragent_list)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		array_useragents = strings.Split(string(content2), "\r\n")

	}

	content, err := ioutil.ReadFile(*dom_list)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	array_dominios := strings.Split(string(content), "\r\n")

	content3, err := ioutil.ReadFile(*patr_list)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	array_patrones := strings.Split(string(content3), "\r\n")

	content4, err := ioutil.ReadFile("signatures")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	patr := strings.Split(string(content4), "\r\n")

	fmt.Println()
	log.Println("Max loop time (s):", *seconds)
	for {
		patr = get(array_dominios, array_useragents, array_patrones, patr, *seconds)
	}
}

func get(array_dominios []string, array_useragents []string, array_patrones []string, patr []string, seconds int) []string {

	rand.Seed(time.Now().Unix())
	d := time.Duration(rand.Intn(seconds))
	f, err := os.OpenFile("signatures", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Println(err)
	}
	f2, err := os.OpenFile("alerts.log", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Println(err)
	}

	for i := range array_dominios {

		rand.Seed(time.Now().Unix())
		intuser := (rand.Intn(len(array_useragents)))

		client := &http.Client{}

		req, err := http.NewRequest("GET", array_dominios[i], nil)

		if err != nil {
			log.Println("PING_FAIL", array_dominios[i])
			return patr
		}
		log.Println("PING", array_dominios[i], array_useragents[intuser], d*time.Second)
		req.Header.Add("User-Agent", array_useragents[intuser])

		resp, err := client.Do(req)

		if err != nil {
			log.Println("PING_FAIL", array_dominios[i])
			return patr
		}

		body, err := ioutil.ReadAll(resp.Body)

		if err != nil {
			log.Println("PING_FAIL", array_dominios[i])
			return patr
		}

		for key := range array_patrones {
			alert := false
			index := suffixarray.New(bytes.ToLower(body))
			ind := index.Lookup(bytes.ToLower([]byte(array_patrones[key])), -1)
			if len(ind) > 0 {
				for shots := range ind {
					if len(patr) == 0 {
						sign := sign_catcher(body, ind[shots])
						patr = append(patr, hex.EncodeToString(sign[:]))
						if _, err = f.WriteString(hex.EncodeToString(sign[:]) + "\r\n"); err != nil {
							log.Println(err)
						}
						alert = true
					}
					tes := false
					for key2 := range patr {
						sign := sign_catcher(body, ind[shots])
						if hex.EncodeToString(sign[:]) == patr[key2] {
							tes = true
						}
					}
					if tes == false {
						sign := sign_catcher(body, ind[shots])
						patr = append(patr, hex.EncodeToString(sign[:]))
						if _, err = f.WriteString(hex.EncodeToString(sign[:]) + "\r\n"); err != nil {
							log.Println(err)
						}
						alert = true
					}
				}
			}
			if alert == true {
				logs := "ALERT " + array_dominios[i] + " " + array_patrones[key]
				log.Println(logs)

				if _, err = f2.WriteString(time.Now().Format(time.RFC3339) + " " + logs + "\r\n"); err != nil {
					log.Println(err)
				}

			}
		}

	}
	time.Sleep(d * time.Second)
	return patr

}

func sign_catcher(str []byte, index int) [16]byte {

	i := 0
	j := 0
	var b1 byte = '<'
	var b2 byte = '>'
	catchinf := 0
	catchsup := 0
	for {

		if str[index-i] == b1 || str[index-i] == b2 {
			catchinf = index - i
			break
		}
		i++
		if index-i < 0 {
			catchinf = 0
			break
		}
	}

	for {
		if str[index+j] == b1 || str[index+j] == b2 {
			catchsup = index + j
			break
		}
		j++
		if index+j > len(str) {
			catchsup = len(str)
			break
		}
	}

	return md5.Sum(str[catchinf+1 : catchsup])
}
