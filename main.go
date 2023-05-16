package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/joho/godotenv"

	"github.com/fsnotify/fsnotify"
)

var (
	device       string = "wlp1s0"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error

	timeout time.Duration = 30 * time.Second
	handle  *pcap.Handle
)

var PBUF = 128

func findOrg(ip string) (org string, _ip string) {
	conn, err := net.Dial("tcp", "whois.arin.net:43")
	if err != nil {
		fmt.Println(err)
		return "", ""
	}

	defer conn.Close()

	fmt.Fprintf(conn, "n %s\r\n", ip)

	scanner := bufio.NewScanner(conn)

	var match []string

	for scanner.Scan() {
		line := scanner.Text()
		re := regexp.MustCompile(`(?i)^OrgName:\s+(.+)`)
		matches := re.FindStringSubmatch(line)
		if len(matches) > 1 {
			match = matches
			break // break out of loop if match found
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println(err)
		return "", ""
	}
	if len(match) > 1 {
		fmt.Printf("Organization Name: %s for IP: %v\n", match[1], ip)
		return match[1], ip
	} else {
		fmt.Println("No match found")
	}

	return "", ""

}

type VirusTotalResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Harmless   int `json:"harmless"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
}

func checkIPVirusTotal(ip string) {
	apiKey := os.Getenv("VT_KEY")
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", ip)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("x-apikey", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	var data VirusTotalResponse
	json.Unmarshal(body, &data)

	malicious := data.Data.Attributes.LastAnalysisStats.Malicious
	suspicious := data.Data.Attributes.LastAnalysisStats.Suspicious

	if malicious > 0 || suspicious > 0 {
		fmt.Printf("Malicious: %d\n", malicious)
		fmt.Printf("Suspicious: %d\n", suspicious)

		// Log the malicious IP
		logStr := fmt.Sprintf("Malicious: %d for %s\n", malicious, ip)
		wLog(logStr)
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

	var path string = "/home/kevin/Dev/Go/dnest/check.txt"
	println("watching: ", path)
	err = watcher.Add(path)
	if err != nil {
		log.Fatal(err)
	}
	<-done
}

func extractIPFromPacket(packet gopacket.Packet) string {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		// Check if the packet is coming from the local network
		if strings.HasPrefix(ip.DstIP.String(), "192.168") {
			// If it is, return the destination IP rather than the source
			return ip.SrcIP.String()
		}
		return ip.SrcIP.String()
	}
	return ""
}

// Log something to a logfile
func wLog(l string) {
	f, err := os.OpenFile("log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	if _, err := f.WriteString(l + "\n"); err != nil {
		log.Fatal(err)
	}
}

func main() {
	// Setting up the basics
	var ips []string
	ips = append(ips, "192.168.1.1")
	godotenv.Load()

	// Run filewatcher in the background
	go filewatcher()

	// Start capturing packets
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		fmt.Println("error: ", err)
	}
	defer handle.Close()

	// Setting up the packet filter (BPF notation)
	var filter string = "dst portrange 49152-65535"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		fmt.Println("error: ", err)
	}

	// Everything went well so far
	fmt.Printf("[+] capturing packets on %s with filter %s\n", device, filter)
	packetsource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Create a channel to receive packets in with a buffer size of PBUF
	recvPackets := make(chan gopacket.Packet, PBUF)
	go func() {
		for packet := range packetsource.Packets() {
			recvPackets <- packet
		}
	}()

	var tempLen int
	for packet := range recvPackets {
		tempLen = len(ips)
		// fmt.Println(packet)
		// fmt.Println(extractIPFromPacket(packet))
		_, ip := findOrg(extractIPFromPacket(packet))
		for _, v := range ips {
			if v == ip {
				continue
			} else {
				ips = append(ips, ip)
			}
		}

		// If the length of the slice has changed, we have a new IP
		// check the new IP against VT.
		if tempLen != len(ips) {
			fmt.Println("New IP found: ", ip)
			fmt.Println("Running VirusTotal check...")
			checkIPVirusTotal(ip)
		}
	}
}