package alias

import _ "unsafe"

//go:linkname InexactOverlap crypto/internal/alias.InexactOverlap
func InexactOverlap(x, y []byte) bool
