package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/akamensky/argparse"
)

var noVerifyTls *bool

func main() {

	fmt.Print(`____   ____.__                       __         .__   __
\   \ /   /|__| ______  _  _________/  |______  |  | |  | __ ___________ 
 \   Y   / |  |/ __ \ \/ \/ /  ___/\   __\__  \ |  | |  |/ // __ \_  __ \
  \     /  |  \  ___/\     /\___ \  |  |  / __ \|  |_|    <\  ___/|  | \/
   \___/   |__|\___  >\/\_//____  > |__| (____  /____/__|_ \\___  >__|   
                   \/           \/            \/          \/    \/       


`)

	parser := argparse.NewParser("viewStalker", "A tool for identifying vulnerable ASP.NET viewstates")
	parser.ExitOnHelp(true)
	noVerifyTls = parser.Flag("k", "no-check-cert", &argparse.Options{Default: true})
	hosts := parser.File("l", "hosts", os.O_RDWR, 0600, &argparse.Options{Required: false, Help: "Path to file with list of hosts to check, one per line"})
	keys := parser.File("M", "mac", os.O_RDWR, 0600, &argparse.Options{Required: true, Help: "machine keys file from blacklist3r"})
	targetAddress := parser.String("a", "address", &argparse.Options{Required: false, Help: "Single host to check"})
	targetViewstate := parser.String("v", "viewstate", &argparse.Options{Required: false, Help: "b64 encoded viewstate"})
	targetModifier := parser.String("m", "modifier", &argparse.Options{Required: false, Help: "modifer"})
	//ysoPath := parser.String("y", "ysoserial", &argparse.Options{Required: false, Help: "Path to ysoserial.net "})
	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
		os.Exit(0)
	}

	keyFile := *keys
	addressValue := *targetAddress
	hostsFile := *hosts
	if len(*targetViewstate) != 0 {
		var vsArray []viewstate
		modifier := *targetModifier

		if len(*targetViewstate) == 0 || len(modifier) == 0 {
			os.Exit(0)
		}
		keyScanner, keyfile, _ := getMachineKeys(keyFile)
		defer keyfile.Close()

		vs := viewstate{
			host:      addressValue,
			viewstate: *targetViewstate,
			modifier:  modifier,
		}

		vsArray = append(vsArray, vs)
		if !bruteKeys(vsArray, keyScanner) {
			fmt.Println(Red("Key not found"))
		}

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
		if !bruteKeys(vsArray, keyScanner) {
			fmt.Println(Red("Key not found"))
		}

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
		if !bruteKeys(vsArray, keyScanner) {
			fmt.Println(Red("Key not found"))
		}
		if err := hostScanner.Err(); err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Print(parser.Usage(err))
	}

}
