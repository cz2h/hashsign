// Problem set 01: Hash based signatures.

// A lot of this lab is set up and templated for you to get used to
// what may be an unfamiliar language (Go).  Go is syntactically
// similar to C / C++ in many ways, including comments.

// In this pset, you need to build a hash based signature system.  We'll use sha256
// as our hash function, and Lamport's simple signature design.

// Currently this compiles but doesn't do much.  You need to implement parts which
// say "your code here".  It also could be useful to make your own functions or
// methods on existing structs, espectially in the forge.go file.

// If you run `go test` and everything passes, you're all set.

// There's probably some way to get it to pass the tests without making an actual
// functioning signature scheme, but I think that would be harder than just doing
// it the right way :)

package main

import (
	// "bytes"
	"crypto/sha256"
	// "encoding/hex"
	"fmt"
)

func main() {

	// Define your message
	textString := "1"
	fmt.Printf("%s\n", textString)

	// convert message into a block
	m := GetMessageFromString(textString)
	fmt.Printf("%x\n", m[:])

	// generate keys
	sec, pub, err := GenerateKey()
	if err != nil {
		panic(err)
	}

	// print pubkey.
	// fmt.Printf("pub:\n%s\n", pub.ToHex())

	// sign message
	sig1 := Sign(m, sec)
	// fmt.Printf("sig1:\n%s\n", sig1.ToHex())

	// verify signature
	worked := Verify(m, pub, sig1)

	// done
	fmt.Printf("Verify worked? %v\n", worked)

	// // Forge signature
	// msgString, _, err := Forge()
	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Printf("forged msg: %s\n", msgString)
	return
}

type Message Block


// GetMessageFromString returns a Message which is the hash of the given string.
func GetMessageFromString(s string) Message {
	return sha256.Sum256([]byte(s))
}

// --- Functions

// GenerateKey takes no arguments, and returns a keypair and potentially an
// error.  It gets randomness from the OS via crypto/rand
// This can return an error if there is a problem with reading random bytes
func GenerateKey() (SecretKey, PublicKey, error) {
	// initialize SecretKey variable 'sec'.  Starts with all 00 bytes.
	var sec SecretKey
	var pub PublicKey

	// Your code here
	// ===
    // Filled secret key.
    for i := 0; i < len(sec.ZeroPre); i ++ {
        sec.ZeroPre[i] = GenrateBlock()
    }

    for i := 0; i < len(sec.OnePre); i ++ {
        sec.OnePre[i] = GenrateBlock()
    }

	// ===
    // Fill public key
    for i := 0; i < len(pub.ZeroHash); i ++ {
        pub.ZeroHash[i] = sec.ZeroPre[i].Hash()
    }

    for i := 0; i < len(pub.OneHash); i ++ {
        pub.OneHash[i] = sec.OnePre[i].Hash()
    }
    
    return sec, pub, nil
}

// Sign takes a hash message and secret key, and returns a signature.
func Sign(msg Message, sec SecretKey) Signature {
	var sig Signature

	// Your code here
	// ===
    for i := 0; i < len(msg); i ++ {
        var byte_string = fmt.Sprintf("%08b", msg[i])
        for j := 0; j < len(byte_string); j ++ {
            if byte_string[j] == '0' {
                sig.Preimage[i * 8 + j] = sec.ZeroPre[i * 8 + j]
            } else {
                sig.Preimage[i * 8 + j] = sec.OnePre[i * 8 + j]
            }
        }
    }
	// ===
	return sig
}

// Verify takes a message, public key and signature, and returns a boolean
// describing the validity of the signature.
// If msg, pub. sig are made in the same endianess, then verify will work correctly.
// 
func Verify(msg Message, pub PublicKey, sig Signature) bool {

	// Your code here
	// ===
    var comp Block;
    for i := 0; i < len(msg); i ++ {
        var byte_string = fmt.Sprintf("%08b", msg[i])
        for j := 0; j < len(byte_string); j ++ {
            if byte_string[j] == '0' {
                comp = pub.ZeroHash[i * 8 + j]
            } else {
                comp = pub.OneHash[i * 8 + j]
            }
            
            if comp != sig.Preimage[i * 8 + j].Hash() {
                return false
            }
        }
    }    
	// ===

	return true
}
