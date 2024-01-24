package dnest

import (
	"fmt"
	"regexp"
)

// This setup requires that the IP is the first "ip address"-like string in the log line.
func IPAddressExtract(line string) string {
	out := fmt.Sprintf("\033[0;32mArg: %s\033[0m", line)
	println(out)

	// re := regexp.MustCompile(`(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
	re := regexp.MustCompile(`(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)

	match := re.FindString(line)

	fmt.Println(match)

	println("\nDONE!\nExiting...")
	if match == "" {
		return "[Warning] No IP found"
	}
	return match
}

// No luck with this..
func IPIsInvalid(ip, log string) bool {
	re := regexp.MustCompile(`[0-9]+/` + ip)
	return re.MatchString(log)
}
