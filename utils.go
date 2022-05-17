package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"log"
	"os"

	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
)

var (
	BadModifier      = errors.New("The provided modifier is bad")
	algorithms       = []string{"SHA1", "HMACSHA256", "HMACSHA384", "HMACSHA512"}
	hashSizes        = []int{20, 32, 48, 64}
	InvalidViewstate = errors.New("Invalid Viewstate")
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

func decodeData(validationKey string, validationAlgorithm string, protectedData []byte, modifier string) (bool, error) {

	byteModifier, err := hex.DecodeString(modifier)
	if err != nil {
		fmt.Println(BadModifier)
	}
	var dataSize int
	var response bool

	byteModifier = reverse(byteModifier)
	hashSize := hashSizes[indexOf(validationAlgorithm, algorithms)]
	dataSize = len(protectedData) - hashSize

	byteHash := make([]byte, hashSize)
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
	if bytes.Compare(computedHash, byteHash) == 0 {
		response = true
		copy(rawData, protectedData)
	} else {
		response = false
	}

	return response, err
}
