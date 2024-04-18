package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
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

	runScan(os.Args, exec.Command)

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

func runScan(args []string, execCmd func(string, ...string) *exec.Cmd) error {
	trivyArgsIndex := findTrivySep(args)
	if trivyArgsIndex < 0 {
		return fmt.Errorf("invalid arguments specified")
	}

	trivyArgs := os.Args[trivyArgsIndex:]

	for i, arg := range trivyArgs {
		fmt.Println("The argument", i, "is", arg)
	}

	log.Println("creating the ignore file")
	path := trivyArgs[2]
	replacer := strings.NewReplacer(":", "")
	cve, err := getCVEs("http://localhost", "3000", replacer.Replace(path))
	if err != nil && errors.Is(err, syscall.ECONNREFUSED) {
		log.Println("could not contact the server - is the server reachable?:", err)
		return err
	} else if err != nil {
		log.Fatal("could not send the get request:", err)
		return err
	}
	writeIgnore(cve)
	log.Println("running trivy with args: ", trivyArgs)
	out, err := execCmd("trivy", trivyArgs...).CombinedOutput()
	if err != nil {
		return err
	}

	log.Println("trivy returned: ", string(out))
	return err
}

func findTrivySep(args []string) int {
	for i, a := range args {
		// trivy args separator is "--"
		if a == "--" {
			if i+1 >= len(args) {
				return -1 // bad case if someone specifies no trivy args
			} else {
				return i + 1 // common case with good args
			}
		}
	}
	return -1 // bad case if no trivy sep & args specified
}

// func containsSlice(haystack []string, needle string) bool {
// 	for _, item := range haystack {
// 		if strings.Contains(item, needle) {
// 			return true
// 		}
// 	}
// 	return false
// }
