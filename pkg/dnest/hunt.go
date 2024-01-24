package dnest

// hunt.go

// Threat hunting code goes here

// Important to note, the VT API is limited to 4 requests per minute, and 500 requests per day
// Which means we'll need to keep track of how many requests we've made, and wait if we've hit the limit
import (
	"fmt"
	"log"
	"os"

	vt "github.com/VirusTotal/vt-go"
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

	// Initialize the hunting ground
	hg := HuntingGround{
		TempDir: WriteTempDir(),
		LogFile: hg.TempDir + "/log.txt",
		KVStore: make(map[string]string),
	}

	fmt.Println("Hunting for threats...")

	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		log.Fatal("VT_API_KEY environment variable not set")
	}

	// Create a new VirusTotal client
	client := vt.NewClient(apiKey)
}

func WriteTempDir() string { // Returns the path to the temp dir
	// Create a temp dir

}

func DelTempDir() {
	// Delete the temp dir
}
