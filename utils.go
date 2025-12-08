package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

var (
	ErrBadModifier      = errors.New("the provided modifier is bad")
	algorithms          = []string{"SHA1", "HMACSHA256", "HMACSHA384", "HMACSHA512"}
	hashSizes           = []int{20, 32, 48, 64}
	ErrInvalidViewstate = errors.New("invalid viewstate")

	// rateLimiter controls HTTP request rate (10 requests per second max)
	rateLimiter = time.NewTicker(100 * time.Millisecond)
)

// debugLog prints debug messages if debug mode is enabled
func debugLog(format string, args ...interface{}) {
	if debugMode != nil && *debugMode {
		timestamp := time.Now().Format("15:04:05.000")
		message := fmt.Sprintf(format, args...)
		fmt.Printf(Teal("[DEBUG %s] %s\n"), timestamp, message)
	}
}

type viewstate struct {
	host          string
	viewstate     string
	modifier      string
	validationKey string
}

func getMachineKeys(keyfile os.File) (*bufio.Scanner, *os.File, error) {
	debugLog("Opening machine keys file: %s", keyfile.Name())
	machineKeys, err := os.Open(keyfile.Name())
	if err != nil {
		debugLog("Error opening machine keys file: %v", err)
		return nil, nil, err
	}

	scannerMAC := bufio.NewScanner(machineKeys)
	debugLog("Machine keys file opened successfully")

	return scannerMAC, machineKeys, err
}

func prepareHosts(hostsfile os.File) (*bufio.Scanner, *os.File, error) {
	debugLog("Opening hosts file: %s", hostsfile.Name())
	hosts, err := os.Open(hostsfile.Name())
	if err != nil {
		debugLog("Error opening hosts file: %v", err)
		return nil, nil, err
	}

	scanner := bufio.NewScanner(hosts)
	debugLog("Hosts file opened successfully")
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

// getHTTPClient returns a configured HTTP client with timeout and TLS settings
func getHTTPClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: *noVerifyTls},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

func makeRequest(address string) string {
	return makeRequestWithRetry(address, 3)
}

func makeRequestWithRetry(address string, maxRetries int) string {
	// Validate URL before processing
	if address == "" {
		debugLog("Skipping empty URL")
		return "0"
	}
	if !strings.HasPrefix(address, "http://") && !strings.HasPrefix(address, "https://") {
		debugLog("Invalid URL (missing protocol): %s", address)
		fmt.Printf(Yellow("Skipping invalid URL: %s (missing http:// or https://)\n"), address)
		return "0"
	}

	// Rate limiting to avoid overwhelming servers
	<-rateLimiter.C
	debugLog("Making HTTP request to: %s", address)

	fmt.Println(Teal("Trying "))
	fmt.Printf(Teal("%s\n"), address)

	client := getHTTPClient()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff with jitter
			backoff := time.Duration(attempt*attempt) * time.Second
			debugLog("Retry attempt %d with %v backoff", attempt, backoff)
			time.Sleep(backoff)
			fmt.Printf(Yellow("Retry attempt %d for %s\n"), attempt, address)
		}

		requestStart := time.Now()
		req, err := http.NewRequestWithContext(ctx, "GET", address, nil)
		if err != nil {
			debugLog("Error creating request: %v", err)
			lastErr = err
			continue
		}

		// Set a reasonable User-Agent
		req.Header.Set("User-Agent", "ViewStalker/1.0")

		resp, err := client.Do(req)
		if err != nil {
			debugLog("Error executing request: %v", err)
			lastErr = err
			continue
		}

		debugLog("HTTP response: status=%d, time=%v", resp.StatusCode, time.Since(requestStart))

		// Ensure body is always closed
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil {
			debugLog("Error reading response body: %v", err)
			lastErr = err
			continue
		}

		debugLog("Response body size: %d bytes", len(body))

		if resp.StatusCode >= 400 {
			debugLog("HTTP error status: %d", resp.StatusCode)
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}

		sb := string(body)
		if strings.Contains(sb, "__VIEWSTATE") {
			debugLog("Viewstate found in response")
			return sb
		}

		debugLog("No viewstate found in response")
		fmt.Println(Yellow("No Viewstate Found, moving on"))
		return "0"
	}

	if lastErr != nil {
		log.Println(Red(fmt.Sprintf("Failed after %d attempts: %v", maxRetries, lastErr)))
	}
	return "0"
}

func extractViewstate(body string) (string, string) {
	debugLog("Parsing HTML to extract viewstate...")
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		debugLog("Error parsing HTML: %v", err)
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
				debugLog("Found __VIEWSTATE: %d bytes", len(viewstate))
			}
			if contains(values, "__VIEWSTATEGENERATOR") {
				modifer = values[len(values)-1]
				debugLog("Found __VIEWSTATEGENERATOR: %s", modifer)
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

// keyCheckJob represents a single key validation job
type keyCheckJob struct {
	vs             viewstate
	validationKey  string
	viewstateBytes []byte
}

// keyCheckResult represents the result of a key validation
type keyCheckResult struct {
	found         bool
	vs            viewstate
	validationKey string
	algorithm     string
}

// ResultOutput represents the output format for positive results
type ResultOutput struct {
	Timestamp     string `json:"timestamp"`
	Host          string `json:"host"`
	ValidationKey string `json:"validation_key"`
	Algorithm     string `json:"algorithm"`
	Viewstate     string `json:"viewstate"`
	Modifier      string `json:"modifier"`
}

func bruteKeys(vsArray []viewstate, keyScanner *bufio.Scanner) bool {
	// Pre-load all keys to avoid scanner concurrency issues
	debugLog("Pre-loading keys from scanner...")
	var keys []string
	for keyScanner.Scan() {
		line := strings.TrimSpace(keyScanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}

		// Keys can be in format: "validationKey,decryptionKey" or just "validationKey"
		// We only need the validation key (first part)
		parts := strings.Split(line, ",")
		key := strings.TrimSpace(parts[0])

		if key != "" {
			keys = append(keys, key)
		} else {
			debugLog("Skipping invalid key entry: %s", line)
		}
	}
	debugLog("Loaded %d keys to test", len(keys))

	fmt.Printf(Purple("Loaded %d keys to test\n"), len(keys))

	// Use a context for cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Process each viewstate
	for vsIdx, vs := range vsArray {
		debugLog("Processing viewstate %d/%d for host: %s", vsIdx+1, len(vsArray), vs.host)
		if vs.viewstate == "" || vs.modifier == "" {
			fmt.Printf(Yellow("Skipping empty viewstate for host: %s\n"), vs.host)
			debugLog("Skipped empty viewstate for: %s", vs.host)
			continue
		}

		viewstateBytes, err := base64.StdEncoding.DecodeString(vs.viewstate)
		if err != nil {
			fmt.Printf(Red("Failed to decode viewstate for %s: %v\n"), vs.host, err)
			debugLog("Base64 decode error for %s: %v", vs.host, err)
			continue
		}
		debugLog("Decoded viewstate: %d bytes", len(viewstateBytes))

		fmt.Printf(Purple("Testing %d keys for host: %s\n"), len(keys), vs.host)

		// Create job channel
		const maxWorkers = 8
		debugLog("Starting %d workers for key validation", maxWorkers)
		jobChan := make(chan keyCheckJob, 100)
		resultChan := make(chan keyCheckResult, maxWorkers)

		var wg sync.WaitGroup
		var keysChecked int
		var mu sync.Mutex

		bruteStart := time.Now()

		// Start worker pool
		for i := 0; i < maxWorkers; i++ {
			wg.Add(1)
			workerID := i + 1
			debugLog("Starting validation worker %d", workerID)
			go func(id int) {
				defer wg.Done()
				for {
					select {
					case <-ctx.Done():
						debugLog("Worker %d cancelled", id)
						return
					case job, ok := <-jobChan:
						if !ok {
							debugLog("Worker %d finished (channel closed)", id)
							return
						}

						mu.Lock()
						keysChecked++
						checked := keysChecked
						mu.Unlock()

						if checked%100 == 0 {
							debugLog("Progress: %d/%d keys checked", checked, len(keys))
						}

						// Try all algorithms for this key
						for _, algorithm := range algorithms {
							match := decode(job.validationKey, algorithm, job.viewstateBytes, job.vs.modifier)
							if match {
								debugLog("MATCH FOUND! Worker %d - Key: %s, Algorithm: %s", id, job.validationKey[:20]+"...", algorithm)
								resultChan <- keyCheckResult{
									found:         true,
									vs:            job.vs,
									validationKey: job.validationKey,
									algorithm:     algorithm,
								}
								return
							}
						}
					}
				}
			}(workerID)
		}

		// Send jobs to workers
		go func() {
			for _, key := range keys {
				select {
				case <-ctx.Done():
					return
				case jobChan <- keyCheckJob{
					vs:             vs,
					validationKey:  key,
					viewstateBytes: viewstateBytes,
				}:
				}
			}
			close(jobChan)
			debugLog("All keys distributed to workers")
		}()

		// Wait for results or completion
		go func() {
			wg.Wait()
			close(resultChan)
			elapsed := time.Since(bruteStart)
			rate := float64(keysChecked) / elapsed.Seconds()
			debugLog("Bruteforce completed: %d keys in %v (%.2f keys/sec)", keysChecked, elapsed, rate)
		}()

		// Check for results
		for result := range resultChan {
			if result.found {
				cancel() // Stop all workers
				debugLog("Key found! Cancelling all workers")
				fmt.Println(Green("\n==============================="))
				fmt.Println(Green("KEY FOUND!!!"))
				fmt.Println(Green("==============================="))
				fmt.Printf("Host: ")
				fmt.Printf(Yellow("%s\n"), result.vs.host)
				fmt.Printf("Validation Key: ")
				fmt.Printf(Green("%s\n"), result.validationKey)
				fmt.Printf("Algorithm: ")
				fmt.Printf(Green("%s\n"), result.algorithm)
				fmt.Println(Green("==============================="))

				// Write to output file if specified
				if outputFile != nil && *outputFile != "" {
					if err := writeResultToFile(*outputFile, result); err != nil {
						fmt.Printf(Red("Error writing to output file: %v\n"), err)
					} else {
						debugLog("Result written to file: %s", *outputFile)
					}
				}

				return true
			}
		}
	}

	return false
}

// writeResultToFile writes a positive result to the output file in JSON format
func writeResultToFile(filename string, result keyCheckResult) error {
	debugLog("Writing result to file: %s", filename)

	output := ResultOutput{
		Timestamp:     time.Now().Format(time.RFC3339),
		Host:          result.vs.host,
		ValidationKey: result.validationKey,
		Algorithm:     result.algorithm,
		Viewstate:     result.vs.viewstate,
		Modifier:      result.vs.modifier,
	}

	// Check if file exists to determine if we need to add array structure
	var results []ResultOutput

	// Try to read existing file
	if data, err := os.ReadFile(filename); err == nil && len(data) > 0 {
		debugLog("Appending to existing file")
		if err := json.Unmarshal(data, &results); err != nil {
			// If unmarshal fails, start fresh
			debugLog("Could not parse existing file, starting fresh: %v", err)
			results = []ResultOutput{}
		}
	} else {
		debugLog("Creating new file")
		results = []ResultOutput{}
	}

	// Append new result
	results = append(results, output)

	// Write back to file
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	debugLog("Successfully wrote result to %s (%d total results)", filename, len(results))
	return nil
}

// buildViewstateObjectFromStdin processes hosts from stdin in a streaming fashion
// without waiting for all input to be read first
func buildViewstateObjectFromStdin(vsArray []viewstate, stdin io.Reader) []viewstate {
	debugLog("Starting streaming stdin reader...")

	const maxWorkers = 10
	const bufferSize = 100

	hostChan := make(chan string, bufferSize)
	resultChan := make(chan viewstate, bufferSize)

	var wg sync.WaitGroup
	var processed, successful int
	var mu sync.Mutex

	// Start worker pool immediately
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		workerID := i + 1
		debugLog("Starting worker %d", workerID)
		go func(id int) {
			defer wg.Done()
			for address := range hostChan {
				debugLog("Worker %d processing: %s", id, address)
				sb := makeRequest(address)
				mu.Lock()
				processed++
				mu.Unlock()
				if sb != "0" {
					vs, mod := extractViewstate(sb)
					if vs != "" && mod != "" {
						vstate := viewstate{
							host:      address,
							modifier:  mod,
							viewstate: vs,
						}
						resultChan <- vstate
						mu.Lock()
						successful++
						mu.Unlock()
						debugLog("Worker %d found valid viewstate for %s", id, address)
					} else {
						debugLog("Worker %d: extraction failed for %s", id, address)
					}
				}
			}
			debugLog("Worker %d finished", id)
		}(workerID)
	}

	// Read from stdin and send to workers concurrently
	go func() {
		reader := bufio.NewReader(stdin)
		lineNum := 0
		hostCount := 0

		debugLog("Reading hosts from stdin...")
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					// Process last line if it doesn't end with newline
					if len(strings.TrimSpace(line)) > 0 {
						lineNum++
						host := strings.TrimSpace(line)
						if host != "" && !strings.HasPrefix(host, "#") {
							hostCount++
							hostChan <- host
							debugLog("Queued host #%d: %s", hostCount, host)
						}
					}
					break
				}
				debugLog("Error reading from stdin: %v", err)
				break
			}

			lineNum++
			host := strings.TrimSpace(line)

			// Skip empty lines and comments
			if host == "" {
				debugLog("Skipping empty line #%d", lineNum)
				continue
			}
			if strings.HasPrefix(host, "#") {
				debugLog("Skipping comment line #%d: %s", lineNum, host)
				continue
			}

			hostCount++
			hostChan <- host
			if hostCount%100 == 0 {
				debugLog("Queued %d hosts so far...", hostCount)
			} else {
				debugLog("Queued host #%d: %s", hostCount, host)
			}
		}

		debugLog("Finished reading stdin: %d hosts queued (from %d lines)", hostCount, lineNum)
		close(hostChan)
	}()

	// Close result channel after all workers are done
	go func() {
		wg.Wait()
		close(resultChan)
		debugLog("All workers completed. Processed: %d, Successful: %d", processed, successful)
	}()

	// Collect results
	for vstate := range resultChan {
		vsArray = append(vsArray, vstate)
	}

	return vsArray
}

func buildViewstateObject(vsArray []viewstate, hostScanner *bufio.Scanner) []viewstate {
	// Collect all hosts first
	debugLog("Pre-loading hosts from scanner...")
	var hosts []string
	for hostScanner.Scan() {
		host := strings.TrimSpace(hostScanner.Text())
		// Skip empty lines and comments
		if host != "" && !strings.HasPrefix(host, "#") {
			hosts = append(hosts, host)
		}
	}
	debugLog("Loaded %d hosts (after filtering empty lines)", len(hosts))

	// Use concurrent processing with a worker pool
	const maxWorkers = 10
	debugLog("Starting worker pool with %d workers", maxWorkers)
	hostChan := make(chan string, len(hosts))
	resultChan := make(chan viewstate, len(hosts))

	var wg sync.WaitGroup
	var processed, successful int
	var mu sync.Mutex

	// Start worker pool
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		workerID := i + 1
		debugLog("Starting worker %d", workerID)
		go func(id int) {
			defer wg.Done()
			for address := range hostChan {
				debugLog("Worker %d processing: %s", id, address)
				sb := makeRequest(address)
				mu.Lock()
				processed++
				mu.Unlock()
				if sb != "0" {
					vs, mod := extractViewstate(sb)
					if vs != "" && mod != "" {
						vstate := viewstate{
							host:      address,
							modifier:  mod,
							viewstate: vs,
						}
						resultChan <- vstate
						mu.Lock()
						successful++
						mu.Unlock()
						debugLog("Worker %d found valid viewstate for %s", id, address)
					} else {
						debugLog("Worker %d: extraction failed for %s", id, address)
					}
				}
			}
			debugLog("Worker %d finished", id)
		}(workerID)
	}

	// Send hosts to workers
	debugLog("Distributing %d hosts to workers", len(hosts))
	for _, host := range hosts {
		hostChan <- host
	}
	close(hostChan)
	debugLog("All hosts distributed, waiting for workers to complete")

	// Close result channel after all workers are done
	go func() {
		wg.Wait()
		close(resultChan)
		debugLog("All workers completed. Processed: %d, Successful: %d", processed, successful)
	}()

	// Collect results
	for vstate := range resultChan {
		vsArray = append(vsArray, vstate)
	}

	return vsArray
}
func decodeData(validationKey string, validationAlgorithm string, protectedData []byte, modifier string) (bool, error) {
	byteModifier, err := hex.DecodeString(modifier)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrBadModifier, err)
	}

	algIndex := indexOf(validationAlgorithm, algorithms)
	if algIndex < 0 || algIndex >= len(hashSizes) {
		return false, fmt.Errorf("invalid validation algorithm: %s", validationAlgorithm)
	}

	byteModifier = reverse(byteModifier)
	hashSize := hashSizes[algIndex]

	if len(protectedData) < hashSize {
		return false, ErrInvalidViewstate
	}

	dataSize := len(protectedData) - hashSize
	byteHash := make([]byte, hashSize)
	copy(byteHash, protectedData[dataSize:dataSize+hashSize])

	byteData := make([]byte, dataSize)
	copy(byteData, protectedData)
	byteData = append(byteData, byteModifier...)

	key, err := hex.DecodeString(validationKey)
	if err != nil {
		return false, fmt.Errorf("failed to decode validation key: %v", err)
	}

	keyedHashAlgorithm := getHMACAlgorithm(validationAlgorithm, key)
	keyedHashAlgorithm.Write(byteData)
	computedHash := keyedHashAlgorithm.Sum(nil)

	return bytes.Equal(computedHash, byteHash), nil
}
