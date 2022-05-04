package main

import (
	"crypto/sha256"
	"math/rand"
	"fmt"
)


// BlockFromByteSlice returns a block from a variable length byte slice.
// Watch out!  Silently ignores potential errors like the slice being too
// long or too short!
func BlockFromByteSlice(by []byte) Block {
	var bl Block
	copy(bl[:], by)
	return bl
}

func GenrateBlock() Block {
	var rand_bytes [32]byte
	rand.Read(rand_bytes[:])
	return BlockFromByteSlice(rand_bytes[:])
}


// A block of data is always 32 bytes long; we're using sha256 and this
// is the size of both the output (defined by the hash function) and our inputs
type Block [32]byte


// ToHex returns a hex encoded string of the block data, with no newlines.
func (self Block) ToHex() string {
	return fmt.Sprintf("%064x", self[:])
}

// Hash returns the sha256 hash of the block.
func (self Block) Hash() Block {
	return sha256.Sum256(self[:])
}

// IsPreimage returns true if the block is a preimage of the argument.
// For example, if Y = hash(X), then X.IsPreimage(Y) will return true,
// and Y.IsPreimage(X) will return false.
func (self Block) IsPreimage(arg Block) bool {
	return self.Hash() == arg
}