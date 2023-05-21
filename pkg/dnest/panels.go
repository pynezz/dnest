package dnest

import (
	"github.com/rivo/tview"
)

type Panel interface {
	// Get the panel's name
	Name() string
	Content() tview.Primitive
}

func NewMenuPanel(name string, content tview.Primitive) {
	box := tview.NewBox().SetBorder(true).SetTitle("Hello, world!")
	if err := tview.NewApplication().SetRoot(box, true).Run(); err != nil {
		panic(err)
	}
}
