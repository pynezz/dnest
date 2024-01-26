package dnest

// hunt.go

// Threat hunting code goes here

// Important to note, the VT API is limited to 4 requests per minute, and 500 requests per day
// Which means we'll need to keep track of how many requests we've made, and wait if we've hit the limit
import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

type BinaryAnalysis struct {
	// The path to the binary file
	BinaryFile string

	// The path to the unpacked binary file
	UnpackedBinaryFile string

	// The path to the log file
	LogFile string

	// The path to the temp dir
	TempDir string

	// The file type
	FileType string

	// The file hash (SHA256, MD5)
	FileHashmap map[string]string

	// The strings in the binary file
	Strings []string
}

// Threat hunting struct
type HuntingGround struct {
	// The path to the temp dir
	TempDir string

	// The path to the log file
	LogFile string

	// Temporary key-value store
	// Key: IP address
	// Value: Log line
	KVStore      map[string]string
	Data         []byte
	DataFilePath string

	// Binary analysis
	BinaryAnalysis *BinaryAnalysis
}

func Hunt() {

	// // Initialize the hunting ground
	// hg := &HuntingGround{
	// 	TempDir: WriteTempDir(),
	// 	LogFile: TempDir + "/log.txt",
	// 	KVStore: make(map[string]string),
	// }

	fmt.Println("Hunting for threats...")

	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		log.Fatal("VT_API_KEY environment variable not set")
	}

	// Create a new VirusTotal client
	// client := vt.NewClient(apiKey)
}

func WriteTempDir() string { // Returns the path to the temp dir
	// Create a temp dir
	var tmpdir string
	return tmpdir
}

func DelTempDir(path string) {
	// Delete the temp dir

	// Prompt the user to delete the temp dir
	// If the user says yes, delete the temp dir
	// If the user says no, exit
	var input string
	fmt.Println("Delete temp dir " + path + "? (y/n)")
	fmt.Scanln(&input)
	if input == "y" {
		// Delete the temp dir
		fmt.Println("Deleting temp dir...")
	} else {
		// Exit
		fmt.Println("Exiting...")
	}

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

func CheckIPVirusTotal(ip string, VT_API_KEY string) {
	apiKey := os.Getenv("VT_KEY")
	if apiKey == "" {
		apiKey = VT_API_KEY
	}
	if apiKey == "" {
		log.Fatal("VT_API_KEY environment variable not set, and no VT_API_KEY set. Use -vtkey to set it")
		os.Exit(1)
	}

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
	json.Unmarshal(body, &data) // Unmarshal the JSON into the data struct, cool stuff

	malicious := data.Data.Attributes.LastAnalysisStats.Malicious
	suspicious := data.Data.Attributes.LastAnalysisStats.Suspicious

	if malicious > 0 || suspicious > 0 {
		fmt.Printf("Malicious: %d\n", malicious)
		fmt.Printf("Suspicious: %d\n", suspicious)

		// Log the malicious IP
		logStr := fmt.Sprintf("- %s\n", ip)
		logStr += fmt.Sprintf("Malicious: %d for %s\n", malicious, ip)
		logStr += fmt.Sprintf("Suspicious: %d for %s\n", suspicious, ip)
		logStr += "--------------------\n"
		wLog(logStr)
	}
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
