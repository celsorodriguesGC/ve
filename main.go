package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
)

var (
	version string
)

type data struct {
	project string
	vuln    string
}

func main() {
	fmt.Println(version)
	cve, err := getCVEs()
	if err != nil {
		log.Println(err)
	}
	writeIgnore(cve)
}

func writeIgnore(cve []byte) {
	f, err := os.OpenFile(".trivyignore", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		log.Println(err)
	}
	_, err = f.Write(cve)
	if err != nil {
		log.Println(err)
	}
}

func getCVEs(serverAddress, serverPort, projectName string) ([]byte, error) {
	data := data{}
	client := http.Client{}
	url := fmt.Sprintf("%s:%s/%s", serverAddress, serverPort, projectName)

	resp, err := client.Get(url)
	if err != nil {
		log.Println(err)
	}
	defer resp.Body.Close()

	httputil.DumpResponse(resp, true)
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		log.Println(err)
	}

	return []byte("CVE-2022-48174"), nil

}
