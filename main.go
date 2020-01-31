package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"os"
	"sync"
)

func fatalIfError(err error) {
	if err != nil {
		panic(err)
	}
}


func main() {
	onlyAscii := flag.Bool("only-ascii", false, "")
	flag.Parse()

	neededHash, err := hex.DecodeString(flag.Arg(0))
	fatalIfError(err)

	if len(neededHash) != 20 /* SHA1 has 20 bytes only */ {
		panic("invalid hash length")
	}

	// May be the hash was entered in the reverse order due to LittleEndian-vs-BigEndian problems,
	// so we also remember the reverse one.
	neededHashReversed := make([]byte, len(neededHash))
	for idx, b := range neededHash {
		neededHashReversed[len(neededHash)-1-idx] = b
	}

	startV := uint8(0x00)
	endV := uint8(0xFF)
	if *onlyAscii {
		startV = uint8(0x20)
		endV = uint8(0x7E)
	}

	inc := func (b []byte) bool {
		for idx, _ := range b {
			realIdx := len(b)-idx-1
			if b[realIdx] < startV {
				b[realIdx] = startV
				return true
			}
			if b[realIdx] < endV {
				b[realIdx]++
				return true
			}
			b[realIdx] = 0
		}
		return false
	}

	var b []byte
	hashInstance := sha1.New()

	try := func(b []byte, hashInstance hash.Hash) {
		hashInstance.Write(b)
		result := hashInstance.Sum(nil)
		hashInstance.Reset()
		if bytes.Compare(result, neededHash) == 0 {
			fmt.Println("found:", b)
			os.Exit(0)
		}
		if bytes.Compare(result, neededHashReversed) == 0 {
			fmt.Println("found:", b, "(reversed input)")
			os.Exit(0)
		}
	}
	for {
		if len(b) < 4 {
			try(b, hashInstance)
			if !inc(b) {
				b = make([]byte, len(b)+1)
			}
			continue
		}

		var wg sync.WaitGroup
		jobs :=  1 + int(endV) - int(startV)
		if startV != 0 {
			jobs++
		}
		wg.Add(jobs)
		for i:=0; i<int(endV)+1; i++ {
			c := make([]byte, len(b))
			copy(c, b)
			c[len(c)-1] = 0
			c[len(c)-2] = 0
			c[len(c)-3] = 0
			c[len(c)-4] = uint8(i)
			go func(c []byte) {
				defer wg.Done()

				startV := c[len(c)-4]
				hashInstance := sha1.New()
				for {
					try(c, hashInstance)
					inc(c)
					if c[len(c)-4] != startV {
						break
					}
				}
			}(c)

			if i < int(startV) {
				i = int(startV)-1
			}
		}
		wg.Wait()

		b[len(b)-4] = endV
		b[len(b)-3] = endV
		b[len(b)-2] = endV
		b[len(b)-1] = endV
		if !inc(b) {
			b = make([]byte, len(b)+1)
		}
		fmt.Println(b)
	}
}
