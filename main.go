package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"syscall"
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
	cve, err := getCVEs("http://localhost", "3000", "x")
	if err != nil && errors.Is(err, syscall.ECONNREFUSED) {
		log.Println("could not contact the server - is the server reachable?:", err)
		return
	} else if err != nil {
		log.Fatal("could not send the get request:", err)
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
		return nil, err
	}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return nil, err
	}
	out := fmt.Sprintf("#cves for %s\n", data.Project)
	for _, cve := range data.Cves {
		out += cve + "\n"
	}

	return []byte(out), nil

}

// func runScan(args []string, execCmd func(string, ...string) *exec.Cmd) error {
// 	trivyArgsIndex := findTrivySep(args)
// 	if trivyArgsIndex < 0 {
// 		return fmt.Errorf("invalid arguments specified")
// 	}

// 	trivyArgs := os.Args[trivyArgsIndex:]

// 	fmt.Println("", trivyArgs)
// 	return nil
// }

// func findTrivySep(args []string) int {
// 	for i, a := range args {
// 		// trivy args separator is "--"
// 		if a == "--" {
// 			if i+1 >= len(args) {
// 				return -1 // bad case if someone specifies no trivy args
// 			} else {
// 				return i + 1 // common case with good args
// 			}
// 		}
// 	}
// 	return -1 // bad case if no trivy sep & args specified
// }

// func containsSlice(haystack []string, needle string) bool {
// 	for _, item := range haystack {
// 		if strings.Contains(item, needle) {
// 			return true
// 		}
// 	}
// 	return false
// }
