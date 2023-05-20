package dnest

// Create a new cell in the honeypots local honeypot hive

// The cell is a basic unit in the beehive.
// It contains some data
type Cell struct {
	name string // name of cell

	// This should preferrably be some binary data to insert into the file (cell)
	data []byte // data in cell

	next *Cell // next cell in list
} // Cell

// The hive is a collection of cells
type Hive struct {
	head *Cell // head of list
} // Hive

/*
Create a new cell in the honeypots local honeypot hive
The cell is a basic unit in the beehive.
It contains some data

@param name string
@param nextCell *Cell
@param fileData []byte
@return *Cell
*/
func (*Cell) NewHoneyCell(name string, nextCell *Cell, fileData []byte) *Cell {
	return &Cell{name: name, next: nextCell, data: fileData}
}

func (*Hive) NewHoneyHive() *Hive {
	return &Hive{head: nil}
}

func (hive *Hive) Add(cell *Cell) {
	if hive.head == nil {
		hive.head = cell
	} else {
		cell.next = hive.head
		hive.head = cell
	}
}

func (hive *Hive) Remove(name string) {
	var prev *Cell = nil
	var curr *Cell = hive.head

	for curr != nil {
		if curr.name == name {
			if prev == nil {
				hive.head = curr.next
			} else {
				prev.next = curr.next
			}
			return
		}
		prev = curr
		curr = curr.next
	}
}

func (hive *Hive) Get(name string) *Cell {
	var curr *Cell = hive.head

	for curr != nil {
		if curr.name == name {
			return curr
		}
		curr = curr.next
	}
	return nil
}
