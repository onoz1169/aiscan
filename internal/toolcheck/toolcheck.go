package toolcheck

import "os/exec"

// Available checks if a binary is on PATH. Returns path and true if found.
func Available(name string) (string, bool) {
	path, err := exec.LookPath(name)
	return path, err == nil
}
