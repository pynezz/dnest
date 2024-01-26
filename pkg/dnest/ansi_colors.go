package dnest

import "fmt"

type Color int

func (c Color) String() string {
	return fmt.Sprintf("\033[%dm", c)
}

const (
	Reset   Color = 0
	Red     Color = 31
	Green   Color = 32
	Yellow  Color = 33
	Blue    Color = 34
	Magenta Color = 35
	Cyan    Color = 36
	White   Color = 37
)

// Colorize a string
func Colorize(s string, c Color) string {
	return fmt.Sprintf("%s%s%s", c.String(), s, Reset.String())
}
