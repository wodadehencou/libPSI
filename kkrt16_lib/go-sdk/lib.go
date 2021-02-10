package kkrt16

/*
#cgo CFLAGS: -I .
#cgo LDFLAGS: -l libkkrt16 -L .

#include <stdlib.h>
#include "kkrt16.h"
*/
import "C"
import (
	"bufio"
	"encoding/binary"
	"math/rand"
	"os"
	"time"
	"unsafe"

	"golang.org/x/crypto/blake2b"
)

func RunSender(sendSet [][]byte, recvSize uint64, server string, port int, malicious bool, statSec int) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	var seeds C.Block
	seeds.high = C.uint64_t(r.Uint64())
	seeds.low = C.uint64_t(r.Uint64())

	cSet := make([]C.Block, len(sendSet))
	var digest []byte
	hasher, _ := blake2b.New(16, nil)
	for i, bs := range sendSet {
		hasher.Reset()
		hasher.Write(bs)
		digest = hasher.Sum(nil)
		cSet[i].low = C.uint64_t(binary.LittleEndian.Uint64(digest[0:8]))
		cSet[i].high = C.uint64_t(binary.LittleEndian.Uint64(digest[8:16]))
	}
	cServer := C.CString(server)
	defer C.free(unsafe.Pointer(cServer))

	var cMalicious C.int
	if malicious {
		cMalicious = 1
	} else {
		cMalicious = 0
	}

	C.run_sender(seeds, &cSet[0], C.uint64_t(len(sendSet)),
		C.uint64_t(recvSize), cServer, C.int(port),
		cMalicious, C.int(statSec))
}

func ReadFile(fn string) [][]byte {
	file, err := os.Open(fn)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	ret := make([][]byte, 0)
	for scanner.Scan() {
		ret = append(ret, scanner.Bytes())
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
	return ret
}
