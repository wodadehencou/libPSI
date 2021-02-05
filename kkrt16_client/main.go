package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	mrand "math/rand"
	"os"
	"time"
)

func main() {
	fmt.Printf("Hello World")
	newData()
}

func newData() {
	f10w := make([][]byte, 100000)
	f20w := make([][]byte, 200000)
	sl := make([]byte, 16)
	for i := 0; i < 250000; i++ {
		io.ReadFull(rand.Reader, sl)
		if i < 100000 {
			f10w[i] = make([]byte, 16)
			copy(f10w[i], sl)
		}
		if i >= 50000 {
			f20w[i-50000] = make([]byte, 16)
			copy(f20w[i-50000], sl)
		}
	}
	mrand.Seed(time.Now().UnixNano())
	mrand.Shuffle(len(f10w), func(i, j int) {
		copy(sl, f10w[i])
		copy(f10w[i], f10w[j])
		copy(f10w[j], sl)
	})
	mrand.Shuffle(len(f20w), func(i, j int) {
		copy(sl, f20w[i])
		copy(f20w[i], f20w[j])
		copy(f20w[j], sl)
	})

	// open output file
	fo10w, err := os.Create("10w.csv")
	if err != nil {
		panic(err)
	}
	// close fo on exit and check for its returned error
	defer fo10w.Close()

	for _, h := range f10w {
		fo10w.WriteString(hex.EncodeToString(h))
		fo10w.WriteString("\n")
	}

	// open output file
	fo20w, err := os.Create("20w.csv")
	if err != nil {
		panic(err)
	}
	// close fo on exit and check for its returned error
	defer fo20w.Close()

	for _, h := range f20w {
		fo20w.WriteString(hex.EncodeToString(h))
		fo20w.WriteString("\n")
	}
}
