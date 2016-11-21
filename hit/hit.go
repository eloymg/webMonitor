package hit

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/hex"
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

type Config struct {
	Seconds       int
	Reset         bool
	DomainList    string
	PatternList   string
	UserAgentList string
}

type Hit struct {
	Config        Config
	SignatureList []string
	PatternList   []string
	DomainList    []string
	UserAgentList []string
}

func (h *Hit) Start() {

	f, err := os.OpenFile("signatures", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Println(err)
	}
	f.Close()
	h.SignatureList = filetoarray("signatures")

	if h.Config.UserAgentList == "" {
		h.UserAgentList = []string{"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
			"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/601.6.17 (KHTML, like Gecko) Version/9.1.1 Safari/601.6.17",
			"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0",
			"Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L Build/IML74K) AppleWebkit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30"}
		fmt.Println("Using default list of user agents (use -a for define a list)")

	} else {

		h.UserAgentList = filetoarray(h.Config.UserAgentList)

	}
	h.DomainList = filetoarray(h.Config.DomainList)
	h.PatternList = filetoarray(h.Config.PatternList)

	fmt.Println(h.DomainList)
	fmt.Println(h.PatternList)

}

func (h *Hit) GoHits() {

	sync := make(chan int)

	for _, domain := range h.DomainList {

		go get(domain, h, sync)
	}
	for {
		<-sync
	}

}

func get(dominio string, h *Hit, sync chan<- int) {

	f, err := os.OpenFile("signatures", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Println(err)
	}

	rUserAgent := rand.Intn(len(h.UserAgentList))
	rTime := rand.Intn(h.Config.Seconds)
	d := time.Duration(rTime)

	userAgent := h.UserAgentList[rUserAgent]

	client := &http.Client{}

	req, err := http.NewRequest("GET", dominio, nil)

	if err != nil {
		log.Println("PING_FAIL", dominio, err)
		sync <- 1
		go get(dominio, h, sync)
		return
	}
	log.Println("PING", dominio, userAgent, d*time.Second)
	req.Header.Add("User-Agent", userAgent)

	resp, err := client.Do(req)

	if err != nil {
		log.Println("PING_FAIL", dominio, " ", err)
		sync <- 1
		go get(dominio, h, sync)
		return
	}

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Println("PING_FAIL", dominio, " ", err)
		sync <- 1
		go get(dominio, h, sync)
		return
	}

	for key := range h.PatternList {
		alert := false
		body = bytes.ToLower(body)
		index := suffixarray.New(body)
		ind := index.Lookup(bytes.ToLower([]byte(h.PatternList[key])), -1)

		if len(ind) > 0 {
			for shots := range ind {
				if len(h.SignatureList) == 0 {
					sign := sign_catcher(body, ind[shots])
					h.SignatureList = append(h.SignatureList, hex.EncodeToString(sign[:]))

					if _, err = f.WriteString(hex.EncodeToString(sign[:]) + "\n"); err != nil {
						log.Println(err)
					}

					alert = true
				}
				tes := false

				sign := sign_catcher(body, ind[shots])

				for key2 := range h.SignatureList {

					if hex.EncodeToString(sign[:]) == h.SignatureList[key2] {
						tes = true
					}

				}
				if tes == false {
					sign := sign_catcher(body, ind[shots])
					h.SignatureList = append(h.SignatureList, hex.EncodeToString(sign[:]))
					if _, err = f.WriteString(hex.EncodeToString(sign[:]) + "\n"); err != nil {
						log.Println(err)
					}
					alert = true
				}
			}
		}
		if alert == true {
			logs := "ALERT " + dominio + " '" + h.PatternList[key] + "'"
			log.Println(logs)
			f2, err := os.OpenFile("alerts.log", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
			if err != nil {
				log.Println(err)
			}
			if _, err = f2.WriteString(time.Now().Format(time.RFC3339) + " " + logs + "\r\n"); err != nil {
				log.Println(err)
			}
			f2.Close()
			//sendMail(dominio, array_patrones[key])
		}
	}

	time.Sleep(d * time.Second)
	sync <- 1
	go get(dominio, h, sync)

}

func sendMail(dominio string, patron string) {

	auth := smtp.PlainAuth("", "XXXX", "XXXX", "XXXX")

	to := []string{"XXXX"}
	msg := []byte("To: XXXXXX\r\n" +
		"Subject: alert domain\r\n" +
		"\r\n" +
		"Alert " + dominio + "\r\n" +
		"Patron " + patron + "\r\n")
	err := smtp.SendMail("XXXXX", auth, "XXXXXXXX", to, msg)
	if err != nil {
		log.Println(err)
	}

}

func filetoarray(path string) []string {

	str := []string{}
	if file, err := os.Open(path); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			str = append(str, scanner.Text())
		}
		if err = scanner.Err(); err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
	} else {
		log.Fatal(err)
		os.Exit(1)
	}

	return str
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
		if index-i <= 0 {
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
		if index+j >= len(str) {
			catchsup = len(str)
			break
		}

	}

	return md5.Sum(str[catchinf+1 : catchsup])
}

func NewHit() *Hit {
	s := &Hit{}
	return s
}
