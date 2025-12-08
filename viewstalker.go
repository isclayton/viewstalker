package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/akamensky/argparse"
)

var (
	noVerifyTls *bool
	debugMode   *bool
	startTime   time.Time
	outputFile  *string
)

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
	debugMode = parser.Flag("d", "debug", &argparse.Options{Default: false, Help: "Enable debug logging"})
	outputFile = parser.String("o", "output", &argparse.Options{Required: false, Help: "Output file for positive results (JSON format)"})
	hosts := parser.File("l", "hosts", os.O_RDWR, 0600, &argparse.Options{Required: false, Help: "Path to file with list of hosts to check, one per line"})
	keys := parser.File("M", "mac", os.O_RDWR, 0600, &argparse.Options{Required: true, Help: "machine keys file from blacklist3r"})
	targetAddress := parser.String("a", "address", &argparse.Options{Required: false, Help: "Single host to check"})
	targetViewstate := parser.String("v", "viewstate", &argparse.Options{Required: false, Help: "b64 encoded viewstate"})
	targetModifier := parser.String("m", "modifier", &argparse.Options{Required: false, Help: "modifer"})
	useStdin := parser.Flag("", "stdin", &argparse.Options{Default: false, Help: "Read hosts from stdin (pipe input)"})
	//ysoPath := parser.String("y", "ysoserial", &argparse.Options{Required: false, Help: "Path to ysoserial.net "})
	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
		os.Exit(0)
	}

	startTime = time.Now()

	if *debugMode {
		fmt.Println(Teal("[DEBUG] Debug logging enabled"))
		fmt.Printf(Teal("[DEBUG] Start time: %s\n"), startTime.Format("2006-01-02 15:04:05"))
	}

	keyFile := *keys
	addressValue := *targetAddress
	hostsFile := *hosts
	stdinMode := *useStdin

	// Auto-detect piped input if not explicitly set
	if !stdinMode {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			stdinMode = true
			debugLog("Auto-detected piped input")
		}
	}

	// Normalize address - add protocol if missing
	if addressValue != "" && !strings.HasPrefix(addressValue, "http://") && !strings.HasPrefix(addressValue, "https://") {
		addressValue = "https://" + addressValue
		debugLog("Auto-prepended https:// to address: %s", addressValue)
	}

	if len(*targetViewstate) != 0 {
		debugLog("Mode: Manual viewstate")
		var vsArray []viewstate
		modifier := *targetModifier

		if len(*targetViewstate) == 0 || len(modifier) == 0 {
			fmt.Println(Red("Error: Both viewstate and modifier are required"))
			os.Exit(1)
		}

		debugLog("Loading machine keys from file: %s", keyFile.Name())
		keyScanner, keyfile, err := getMachineKeys(keyFile)
		if err != nil {
			fmt.Printf(Red("Error loading machine keys: %v\n"), err)
			os.Exit(1)
		}
		defer keyfile.Close()

		vs := viewstate{
			host:      addressValue,
			viewstate: *targetViewstate,
			modifier:  modifier,
		}
		debugLog("Viewstate length: %d bytes, Modifier: %s", len(*targetViewstate), modifier)

		vsArray = append(vsArray, vs)
		debugLog("Starting key bruteforce with 1 viewstate")
		if !bruteKeys(vsArray, keyScanner) {
			fmt.Println(Red("Key not found"))
			debugLog("Bruteforce completed - no key found")
		}

	} else if addressValue != "" {
		debugLog("Mode: Single host")
		debugLog("Target: %s", addressValue)
		var vsArray []viewstate
		sb := makeRequest(addressValue)
		if sb == "0" {
			fmt.Println(Red("Failed to retrieve viewstate from target"))
			os.Exit(1)
		}

		debugLog("Response received, extracting viewstate...")
		vstate, mod := extractViewstate(sb)
		if vstate == "" || mod == "" {
			fmt.Println(Red("Failed to extract viewstate or modifier from response"))
			os.Exit(1)
		}
		debugLog("Viewstate extracted - length: %d bytes, modifier: %s", len(vstate), mod)

		vs := viewstate{
			host:      addressValue,
			viewstate: vstate,
			modifier:  mod,
		}

		debugLog("Loading machine keys from file: %s", keyFile.Name())
		keyScanner, keyfile, err := getMachineKeys(keyFile)
		if err != nil {
			fmt.Printf(Red("Error loading machine keys: %v\n"), err)
			os.Exit(1)
		}
		defer keyfile.Close()

		vsArray = append(vsArray, vs)
		debugLog("Starting key bruteforce with 1 viewstate")
		if !bruteKeys(vsArray, keyScanner) {
			fmt.Println(Red("Key not found"))
			debugLog("Bruteforce completed - no key found")
		}

	} else if stdinMode {
		debugLog("Mode: Stdin (piped input)")
		debugLog("Reading hosts from stdin...")

		var vsArray []viewstate
		debugLog("Loading machine keys from file: %s", keyFile.Name())
		keyScanner, keyfile, err := getMachineKeys(keyFile)
		if err != nil {
			fmt.Printf(Red("Error loading machine keys: %v\n"), err)
			fmt.Print(parser.Usage(err))
			os.Exit(1)
		}
		defer keyfile.Close()

		// Stream hosts from stdin and process concurrently
		debugLog("Starting streaming stdin processing...")
		scanStart := time.Now()
		vsArray = buildViewstateObjectFromStdin(vsArray, os.Stdin)
		debugLog("Viewstate collection completed in %v", time.Since(scanStart))

		fmt.Printf(Purple("Got: %d viewstate(s)\n"), len(vsArray))

		if len(vsArray) == 0 {
			fmt.Println(Yellow("No valid viewstates found to test"))
			debugLog("No viewstates found - exiting")
			os.Exit(0)
		}

		debugLog("Starting key bruteforce with %d viewstate(s)", len(vsArray))
		if !bruteKeys(vsArray, keyScanner) {
			fmt.Println(Red("Key not found"))
			debugLog("Bruteforce completed - no key found")
		}

		// Check for scanner errors after key bruteforcing
		if err := keyScanner.Err(); err != nil {
			fmt.Printf(Red("Error during key scanning: %v\n"), err)
			os.Exit(1)
		}

		debugLog("Total execution time: %v", time.Since(startTime))

	} else if !argparse.IsNilFile(&hostsFile) {
		debugLog("Mode: Multi-host scan")
		debugLog("Hosts file: %s", hostsFile.Name())

		var vsArray []viewstate
		debugLog("Loading machine keys from file: %s", keyFile.Name())
		keyScanner, keyfile, err := getMachineKeys(keyFile)
		if err != nil {
			fmt.Printf(Red("Error loading machine keys: %v\n"), err)
			fmt.Print(parser.Usage(err))
			os.Exit(1)
		}
		defer keyfile.Close()

		debugLog("Loading hosts from file...")
		hostScanner, hostsfile, err := prepareHosts(hostsFile)
		if err != nil {
			fmt.Printf(Red("Error loading hosts file: %v\n"), err)
			fmt.Print(parser.Usage(err))
			os.Exit(1)
		}
		defer hostsfile.Close()

		// Check for scanner errors before processing
		if err := hostScanner.Err(); err != nil {
			fmt.Printf(Red("Error reading hosts file: %v\n"), err)
			os.Exit(1)
		}

		debugLog("Building viewstate objects with concurrent workers...")
		scanStart := time.Now()
		vsArray = buildViewstateObject(vsArray, hostScanner)
		debugLog("Viewstate collection completed in %v", time.Since(scanStart))

		// Check for scanner errors after processing
		if err := hostScanner.Err(); err != nil {
			fmt.Printf(Red("Error during host scanning: %v\n"), err)
			os.Exit(1)
		}

		fmt.Printf(Purple("Got: %d viewstate(s)\n"), len(vsArray))

		if len(vsArray) == 0 {
			fmt.Println(Yellow("No valid viewstates found to test"))
			debugLog("No viewstates found - exiting")
			os.Exit(0)
		}

		debugLog("Starting key bruteforce with %d viewstate(s)", len(vsArray))
		if !bruteKeys(vsArray, keyScanner) {
			fmt.Println(Red("Key not found"))
			debugLog("Bruteforce completed - no key found")
		}

		// Check for scanner errors after key bruteforcing
		if err := keyScanner.Err(); err != nil {
			fmt.Printf(Red("Error during key scanning: %v\n"), err)
			os.Exit(1)
		}

		debugLog("Total execution time: %v", time.Since(startTime))
	} else {
		fmt.Print(parser.Usage(err))
		os.Exit(1)
	}

}
