package gitcrypt

import "golang.org/x/tools/godoc/vfs"

// GitCrypt is the namespace
type GitCrypt struct {
	// Debug represents whether debug output will be enabled. Do not turn
	// this on until you really mean it.
	Debug bool
	// Vfs represents an optional virtual filesystem. If it is nil, the
	// standard OS file opening functions will be used.
	Vfs vfs.FileSystem
}
