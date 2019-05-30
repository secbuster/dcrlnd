package lnwire

import (
	"bytes"
	"github.com/decred/dcrlnd/lnwire"
)

func FuzzReadMessage(data []byte) int {

	msg, err := lnwire.ReadMessage(bytes.NewReader(data), 0)
	if err != nil {
		return 0
	}

	w := bytes.NewBuffer([]byte{})
	_, err = lnwire.WriteMessage(w, msg, 0)
	if err != nil {
		return 0
	}

	return 1
}
