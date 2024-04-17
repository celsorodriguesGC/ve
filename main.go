package main

import (
	"fmt"
	"log"
	"os"
)

var (
	version string
)

func main() {
	fmt.Println(version)
	writeIgnore()
}

func writeIgnore() {
	f, err := os.OpenFile(".trivyignore", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal(err)
	}
	_, err = f.Write([]byte("CVE-2022-48174"))
	if err != nil {
		log.Fatal(err)
	}
}
