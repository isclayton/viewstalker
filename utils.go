package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"golang.org/x/net/html"
)

var (
	ErrBadModifier      = errors.New("the provided modifier is bad")
	algorithms          = []string{"SHA1", "HMACSHA256", "HMACSHA384", "HMACSHA512"}
	hashSizes           = []int{20, 32, 48, 64}
	ErrInvalidViewstate = errors.New("invalid viewstate")
)

type viewstate struct {
	host          string
	viewstate     string
	modifier      string
	validationKey string
}

func getMachineKeys(keyfile os.File) (*bufio.Scanner, *os.File, error) {
	machineKeys, err := os.Open(keyfile.Name())

	scannerMAC := bufio.NewScanner(machineKeys)

	return scannerMAC, machineKeys, err
}

func prepareHosts(hostsfile os.File) (*bufio.Scanner, *os.File, error) {
	hosts, err := os.Open(hostsfile.Name())

	scanner := bufio.NewScanner(hosts)
	return scanner, hosts, err
}

func indexOf(element string, data []string) int {
	for k, v := range data {
		if element == v {
			return k
		}
	}
	return -1
}

func reverse(bytes []byte) []byte {
	for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}
	return bytes
}

func getHMACAlgorithm(digestMethod string, validationKey []byte) hash.Hash {
	switch digestMethod {
	case "SHA1":
		return hmac.New(sha1.New, validationKey)
	case "HMACSHA256":
		return hmac.New(sha256.New, validationKey)
	case "HMACSHA384":
		return hmac.New(sha512.New384, validationKey)
	case "HMACSHA512":
		return hmac.New(sha512.New, validationKey)
	}
	return hmac.New(sha1.New, validationKey)
}
func makeRequest(address string) string {

	fmt.Println(Teal("Trying "))
	fmt.Printf(Teal("%s\n"), address)
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: *noVerifyTls}
	resp, err := http.Get(address)
	if err != nil {
		log.Println(Red(err))
		return "0"
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println(Red(err))
		return "0"
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
		log.Println(Red(err))
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
	if len(viewstate) == 0 {
		return false
	}
	return bytes.Equal(viewstate[:2], PREAMBLE)
}
func decode(validationKey string, validationAlgorithm string, protectedData []byte, modifier string) bool {
	var match bool
	var err error
	if validate(protectedData) {
		//fmt.Println(protectedData)
		match, err = decodeData(validationKey, validationAlgorithm, protectedData, modifier)
		if err != nil {
			log.Print(Red(err))
		}
	}

	return match
}

func bruteKeys(vsArray []viewstate, keyScanner *bufio.Scanner) bool {
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
					return true
				}
			}

		}
	}
	return false
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
func decodeData(validationKey string, validationAlgorithm string, protectedData []byte, modifier string) (bool, error) {

	byteModifier, err := hex.DecodeString(modifier)
	if err != nil {
		fmt.Println(ErrBadModifier)
	}
	var dataSize int
	var response bool

	byteModifier = reverse(byteModifier)
	hashSize := hashSizes[indexOf(validationAlgorithm, algorithms)]
	byteHash := make([]byte, hashSize)

	//fmt.Println(hashSize, len(byteHash), len(protectedData), protectedData)
	if len(protectedData) < hashSize {
		fmt.Println(Yellow("Viewstate with no data detected\n"))
		dataSize = 0

		return false, ErrInvalidViewstate
	} else {
		dataSize = len(protectedData) - hashSize

	}
	//fmt.Println(hashSize, dataSize, validationAlgorithm)
	copy(byteHash, protectedData[dataSize:dataSize+hashSize])
	byteData := make([]byte, dataSize)
	copy(byteData, protectedData)
	byteData = append(byteData, byteModifier...)
	key, _ := hex.DecodeString(validationKey)
	keyedHashAlgorithm := getHMACAlgorithm(validationAlgorithm, key)
	rawData := make([]byte, dataSize)
	keyedHashAlgorithm.Write(byteData)
	computedHash := make([]byte, hashSize)
	computedHash = keyedHashAlgorithm.Sum(nil)

	if err != nil {
		log.Fatal(err)
	}
	if bytes.Equal(computedHash, byteHash) {
		response = true
		copy(rawData, protectedData)
	} else {
		response = false
	}

	return response, err
}
