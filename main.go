package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/rivo/tview"

	"github.com/fsnotify/fsnotify"

	"github.com/pynezz/dnest/pkg/dnest"
)

type Args struct {
	ConfigFile string
}

// Global args variable
var (
	variables = &Args{
		ConfigFile: "",
	}
)

var (
	// The honeypot hive
	hive *dnest.Hive = nil
	cell *dnest.Cell = nil
)

func displayMenu() {
	fmt.Println("1. Add a file to the honeypot")
	fmt.Println("2. Remove a file from the honeypot")
	fmt.Println("3. List all files in the honeypot")
	fmt.Println("4. Exit")

	fmt.Print("Enter your choice: ")

	textArea := tview.NewTextView()
	textArea.SetBorder(true).SetTitle("Hello, world!")
	if err := tview.NewApplication().SetRoot(textArea, true).Run(); err != nil {
		panic(err)
	}

	if choice, err := bufio.NewReader(os.Stdin).ReadString('\n'); err == nil {
		switch strings.TrimSpace(choice) {
		case "1":
			fmt.Println("Add a file to the honeypot")
			fmt.Print("Enter the file name: ")
			if fileName, err := bufio.NewReader(os.Stdin).ReadString('\n'); err == nil {
				fmt.Println("Adding file: ", strings.TrimSpace(fileName))

				// TODO: Add file to honeypot
				cell = cell.NewHoneyCell(strings.TrimSpace(fileName), cell, []byte("wallet.dat"))
			} else {
				fmt.Println(err)
			}
		case "2":
			fmt.Println("Remove a file from the honeypot")
			fmt.Print("Enter the file name: ")
			if fileName, err := bufio.NewReader(os.Stdin).ReadString('\n'); err == nil {
				fmt.Println("Removing file: ", strings.TrimSpace(fileName))
				// removeCell(strings.TrimSpace(fileName)) // TODO
			} else {
				fmt.Println(err)
			}
		case "3":
			fmt.Println("List all files in the honeypot")
			// listCells() // TODO
		case "4":
			fmt.Println("Exit")
			os.Exit(0)
		default:
			fmt.Println("Invalid choice")
		}
	} else {
		fmt.Println(err)
	}
}

func filewatcher() {
	println("filewatcher start")
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}

	defer watcher.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				log.Println("event:", event)
				if event.Op&fsnotify.Write == fsnotify.Write {
					log.Println("modified file:", event.Name)
				}
				if event.Op&fsnotify.Remove == fsnotify.Remove {
					log.Println("removed file:", event.Name)
				}
				if event.Op&fsnotify.Rename == fsnotify.Rename {
					log.Println("renamed file:", event.Name)
				}
				if event.Op&fsnotify.Chmod == fsnotify.Chmod {
					log.Println("chmod file:", event.Name)
				}
				if event.Op&fsnotify.Create == fsnotify.Create {
					log.Println("create file:", event.Name)
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("error:", err)
			}
		}
	}()

	// var path string = "/home/kevin/Dev/Go/dnest/check.txt" // Linux
	wd, _ := os.Getwd()
	var path string = wd + "\\check.txt"

	println("watching: ", path)
	err = watcher.Add(path)
	if err != nil {
		log.Fatal(err)
	}
	<-done
}

func parseArgs() map[string]string {
	args := os.Args

	parsed := make(map[string]string)

	var ip string = ""
	var VT_API_KEY string = ""
	var configFile string = ""

	for i, arg := range args {
		if arg == "-ip" && i < len(args)-1 {
			ip = args[i+1]
		}
		if arg == "-vtkey" && i < len(args)-1 {
			VT_API_KEY = args[i+1]
		}
		if arg == "-config" && i < len(args)-1 {
			configFile = args[i+1]
		}
	}

	if ip != "" {
		ip = dnest.IPAddressExtract(ip)
	} else {
		fmt.Println(dnest.Colorize("[!]", dnest.Red) + " No IP address provided")
		// os.Exit(1)
	}

	parsed["ip"] = ip
	parsed["vtkey"] = VT_API_KEY
	parsed["config"] = configFile

	return parsed
}

func main() {

	args := parseArgs()

	ip := args["ip"]
	VT_API_KEY := args["vtkey"]
	variables.ConfigFile = args["config"]

	readConf()

	dnest.CheckIPVirusTotal(ip, VT_API_KEY)

	// return
	// displayMenu()

	// Run filewatcher in the background
	// go filewatcher()

}

func readConf() {
	fmt.Printf("%s Reading config file (%s)\n", dnest.Colorize("[+]", dnest.Green), variables.ConfigFile)
	// Read config file
	// If no config file, create one
	// If config file, read it
	// If config file, parse it

	// Read
	configFile := variables.ConfigFile

	// Check if the config file exists
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		defaultConf() // Create default config if not exists
	}

	// Now open the file for reading
	f, err := os.Open(configFile)
	if err != nil {
		log.Fatalf("Error opening config file: %s", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line)
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading config file: %s\n", err)
		os.Exit(1)
	}

}

func defaultConf() {
	conf := `	# This is the default config file for dnest
	# You can change the config file with the -config flag
	# The config file is used to store variables that are used in dnest

	# Use VirusTotal
	USE_VT = true

	# Use ThreatFox
	USE_TF = true

	# Use Abuse[dot]ch
	USE_ABUSECH = true

	## Filesystem stuff
	# Directory for log files
	LOG_DIR = "/var/log/dnest"

	# Directory for honeypot files
	HONEYPOT_DIR = "/var/lib/dnest"

	# Directory for unpacked files
	UNPACKED_DIR = "/var/lib/dnest/unpacked"

	# Directory for nginx logs
	NGINX_LOGS = "/var/log/nginx/access.log"
	`

	err := os.WriteFile("dnest.conf", []byte(conf), 0644)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s Created default config file", dnest.Colorize("[+]", dnest.Green))
}
