package dnest

// binaryanalysis.go

// Analyze a binary file and return results

// Use in build stuff like "strings", and "file" to get some info about the binary

import (
	"os/exec"
)

func GetFileType() {

}

func GetFileHash() {

}

func GetStrings() {

	err := exec.Command("strings ", fileName)
}

// If the file is a type of packed file, try to unpack it
// First, detect the packer
// Then, unpack it
// Finally, analyze the unpacked file
// UPX is common and start with "UPX!"
func Unpack() {
}
