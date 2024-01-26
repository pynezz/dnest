package dnest

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/joho/godotenv"
)

var (
	device       string = "wlp1s0"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error

	timeout time.Duration = 30 * time.Second
	handle  *pcap.Handle

	VT_API_KEY string = ""

	PBUF = 128
)

func StartPacketInspector() {
	// Setting up the basics
	var ips []string
	ips = append(ips, "192.168.1.1")
	godotenv.Load()

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
		_, ip := FindOrg(extractIPFromPacket(packet))
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
			CheckIPVirusTotal(ip, VT_API_KEY)
		}
	}
}

func FindOrg(ip string) (org string, _ip string) {
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
