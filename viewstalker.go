package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/akamensky/argparse"
)

func main() {

	parser := argparse.NewParser("viewStalker", "A tool for identifying vulnerable ASP.NET viewstates")
	hosts := parser.File("l", "hosts", os.O_RDWR, 0600, &argparse.Options{Required: false, Help: "Path to file with list of hosts to check, one per line"})
	keys := parser.File("M", "mac", os.O_RDWR, 0600, &argparse.Options{Required: false, Help: "machine keys file from blacklist3r"})
	address := parser.String("a", "address", &argparse.Options{Required: false, Help: "Single host to check"})
	testViewstate := parser.String("v", "viewstate", &argparse.Options{Required: false, Help: "b64 encoded viewstate"})
	testModifier := parser.String("m", "modifier", &argparse.Options{Required: false, Help: "modifer"})
	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
		log.Fatal(err)
	}

	keyFile := *keys
	addressValue := *address
	hostsFile := *hosts
	if len(*testViewstate) != 0 {
		var vsArray []viewstate
		modifier := *testModifier

		if len(*testViewstate) == 0 || len(modifier) == 0 {
			fmt.Print(parser.Usage(err))
			fmt.Println(Red("Required: viewstate, modifier"))
			os.Exit(0)
		}
		keyScanner, keyfile, _ := getMachineKeys(keyFile)
		defer keyfile.Close()

		vs := viewstate{
			host:      addressValue,
			viewstate: *testViewstate,
			modifier:  modifier,
		}

		vsArray = append(vsArray, vs)
		bruteKeys(vsArray, keyScanner)

	} else if strings.Contains(addressValue, "http") {
		var vsArray []viewstate
		sb := makeRequest(addressValue)
		vstate, mod := extractViewstate(sb)
		vs := viewstate{
			host:      addressValue,
			viewstate: vstate,
			modifier:  mod,
		}

		keyScanner, keyfile, _ := getMachineKeys(keyFile)
		defer keyfile.Close()

		vsArray = append(vsArray, vs)
		bruteKeys(vsArray, keyScanner)

	} else if !argparse.IsNilFile(&hostsFile) {

		var vsArray []viewstate
		keyScanner, keyfile, err := getMachineKeys(keyFile)
		if err != nil {
			fmt.Print(parser.Usage(err))
		}
		defer keyfile.Close()

		hostScanner, hostsfile, err := prepareHosts(hostsFile)
		if err != nil {
			fmt.Print(parser.Usage(err))
		}
		defer hostsfile.Close()

		vsArray = buildViewstateObject(vsArray, hostScanner)

		fmt.Printf(Purple("Got: %d viewstate(s)\n"), len(vsArray))
		bruteKeys(vsArray, keyScanner)
		if err := hostScanner.Err(); err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Print(parser.Usage(err))
	}

}
