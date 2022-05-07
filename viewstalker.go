package main

import (
	"bufio"
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
		fmt.Println("Moving on")
	}
	return "0"
}

func extractViewstate(body string) [2]string {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		log.Fatal(err)
	}
	var f func(*html.Node)
	var retValues [2]string
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			var values []string
			for _, a := range n.Attr {
				values = append(values, a.Val)
			}
			if contains(values, "__VIEWSTATE") {
				retValues[0] = values[len(values)-1]
			}
			if contains(values, "__VIEWSTATEGENERATOR") {
				retValues[1] = values[len(values)-1]
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	return retValues
}

func contains(array []string, term string) bool {
	for _, v := range array {
		if v == term {
			return true
		}
	}
	return false
}
func main() {

	parser := argparse.NewParser("viewStalker", "A tool for identifying vulnerable ASP.NET viewstates")
	hosts := parser.File("l", "hosts", os.O_RDWR, 0600, &argparse.Options{Required: false, Help: "Path to file with list of hosts to check, one per line"})
	address := parser.String("a", "address", &argparse.Options{Required: false, Help: "Single host to check"})
	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}
	addressValue := *address
	hostsFile := *hosts
	if strings.Contains(addressValue, "http") {
		sb := makeRequest(addressValue)
		fmt.Println(extractViewstate(sb))
	} else if !argparse.IsNilFile(&hostsFile) {
		fmt.Println("Checking for hosts file")
		file, err := os.Open(hostsFile.Name())
		if err != nil {
			fmt.Print(parser.Usage(err))
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			sb := makeRequest(scanner.Text())
			fmt.Println(extractViewstate(sb))
		}

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Print(parser.Usage(err))
	}

}
