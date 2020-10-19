package main

import (
	"flag"
	"fmt"
	"os"
)

// #cgo LDFLAGS: -L./build -l:libdes.a
// #include "des.h"
import "C"

func main() {
	var inputStr = flag.String("input", "", "input string")
	flag.Parse()
	if inputStr == nil || *inputStr == "" {
		flag.PrintDefaults()
		fmt.Errorf("empty input\n")
		os.Exit(1)
	}
	var key C.uchar
	var keysets = make([]C.key_set, 17)
	var input = []C.uchar(*inputStr)
	var cached_input = input
	var output = make([]C.uchar, len(*inputStr)*2)

	C.generate_key(&key)
	C.generate_sub_keys(&key, &keysets[0])

	fmt.Printf("before encryption:%v\n", input)
	C.process_message(&input[0], &output[0], &keysets[0], 1)
	fmt.Printf("after des encryption:%v\n", output)
	C.process_message(&output[0], &input[0], &keysets[0], 0)
	fmt.Printf("after des decryption:%v\n", input)

	for i, _ := range input {
		if input[i] == cached_input[i] {
			continue
		} else {
			fmt.Printf("error~\n")
			os.Exit(1)
		}
	}
	fmt.Printf("Test passed\n")

}
