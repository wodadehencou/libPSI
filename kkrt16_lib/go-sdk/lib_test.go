package kkrt16

import "testing"

func Test_Basic(t *testing.T) {
	RunSender(ReadFile("/etc/passwd"), 10, "localhost", 21021, false, 40)
}
