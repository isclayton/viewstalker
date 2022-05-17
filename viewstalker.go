package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/akamensky/argparse"
	"golang.org/x/net/html"
)

func makeRequest(address string) string {
	fmt.Println(Teal("Trying "))
	fmt.Printf(Teal("%s\n"), address)
	resp, err := http.Get(address)
	if err != nil {
		log.Fatalln(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(body)

	if strings.Contains(sb, "__VIEWSTATE") {
		return sb
	} else {
		fmt.Println(Yellow("No Viewstate Found, moving on"))
	}
	return "0"
}

func extractViewstate(body string) (string, string) {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		log.Fatal(err)
	}
	var f func(*html.Node)
	var modifer string
	var viewstate string
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			var values []string
			for _, a := range n.Attr {
				values = append(values, a.Val)
			}
			if contains(values, "__VIEWSTATE") {
				viewstate = values[len(values)-1]
			}
			if contains(values, "__VIEWSTATEGENERATOR") {
				modifer = values[len(values)-1]
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	return viewstate, modifer
}

func contains(array []string, term string) bool {
	for _, v := range array {
		if v == term {
			return true
		}
	}
	return false
}
func containsInt(array []int, term int) bool {
	for _, v := range array {
		if v == term {
			return true
		}
	}
	return false
}

func validate(viewstate []byte) bool {
	var PREAMBLE = []byte{255, 1}
	return bytes.Equal(viewstate[:2], PREAMBLE)
}
func decode(validationKey string, validationAlgorithm string, protectedData []byte, modifier string) bool {
	var match bool
	var err error
	if validate(protectedData) {
		match, err = decodeData(validationKey, validationAlgorithm, protectedData, modifier)
		if err != nil {
			log.Fatal(err)
		}
	}

	return match
}

func bruteKeys(vsArray []viewstate, keyScanner *bufio.Scanner) {
	fmt.Println("iek")
	for _, vs := range vsArray {
		var validationKey string
		for keyScanner.Scan() {
			validationKey = strings.Split(keyScanner.Text(), " ")[0]
			viewstate, _ := base64.StdEncoding.DecodeString(vs.viewstate)
			modifier := vs.modifier
			for _, element := range algorithms {
				match := decode(validationKey, element, viewstate, modifier)
				if match {
					vs.validationKey = validationKey
					fmt.Println(Green("KEY FOUND!!!"))
					fmt.Printf("Host: ")
					fmt.Printf(Yellow(" %s \n"), vs.host)
					fmt.Printf("Validation Key: ")
					fmt.Printf(Green("%s"), vs.validationKey)
				}
			}

		}

	}
}

func buildViewstateObject(vsArray []viewstate, hostScanner *bufio.Scanner) []viewstate {
	//var vsArray []viewstate
	for hostScanner.Scan() {
		address := hostScanner.Text()
		sb := makeRequest(address)
		vs, mod := extractViewstate(sb)
		vstate := viewstate{
			host:      address,
			modifier:  mod,
			viewstate: vs,
		}
		vsArray = append(vsArray, vstate)

	}
	return vsArray
}

func main() {

	parser := argparse.NewParser("viewStalker", "A tool for identifying vulnerable ASP.NET viewstates")
	hosts := parser.File("l", "hosts", os.O_RDWR, 0600, &argparse.Options{Required: false, Help: "Path to file with list of hosts to check, one per line"})
	keys := parser.File("M", "mac", os.O_RDWR, 0600, &argparse.Options{Required: false, Help: "machine keys file from blacklist3r"})
	address := parser.String("a", "address", &argparse.Options{Required: false, Help: "Single host to check"})
	test := parser.String("t", "test", &argparse.Options{Required: false, Help: "Single host to check"})
	testViewstate := parser.String("v", "viewstate", &argparse.Options{Required: false, Help: "b64 encoded viewstate"})
	testModifier := parser.String("m", "modifier", &argparse.Options{Required: false, Help: "modifer"})
	testValKey := parser.String("k", "key", &argparse.Options{Required: false, Help: "validation key"})
	testAlgo := parser.String("s", "algo", &argparse.Options{Required: false, Help: "algorithm for validation"})
	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
		log.Fatal(err)
	}

	keyFile := *keys
	testflag := *test
	addressValue := *address
	hostsFile := *hosts

	if strings.Contains(testflag, "viewstate") {
		viewstate := *testViewstate
		valKey := *testValKey
		modifier := *testModifier
		algo := *testAlgo

		if len(viewstate) == 0 || len(valKey) == 0 || len(modifier) == 0 || len(algo) == 0 {
			fmt.Print(parser.Usage(err))
			fmt.Println(Red("Required: viewstate, modifier, algo, key"))
			os.Exit(0)
		}
		vs, err := base64.StdEncoding.DecodeString(viewstate)
		if err != nil {
			log.Fatal(err)
		}
		match := decode(valKey, algo, vs, modifier)
		if match {
			fmt.Println(Green("KEY FOUND!!!"))
		} else {
			fmt.Println(Red("KEY NOT FOUND :("))
		}

	} else if strings.Contains(addressValue, "http") {
		sb := makeRequest(addressValue)
		fmt.Println(sb)
		//vs, mod := extractViewstate(sb)

		//match := decode(, element, vs, mod)

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
