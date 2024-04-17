package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

var (
	version string
)

type Data struct {
	Project string   `json:"project"`
	Cves    []string `json:"cves"`
}

func main() {
	fmt.Println(version)
	cve, err := getCVEs("http://localhost", "3000", "basket")
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
	data := Data{}
	client := http.Client{}
	url := fmt.Sprintf("%s:%s/%s", serverAddress, serverPort, projectName)

	resp, err := client.Get(url)
	if err != nil {
		log.Println(err)
	}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		log.Println(err)
	}
	out := fmt.Sprintf("#cves for %s\n", data.Project)
	for _, cve := range data.Cves {
		out += cve + "\n"
	}

	return []byte(out), nil

}
