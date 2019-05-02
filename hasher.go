package passwordtool

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

// Hasher type
type Hasher interface {
	fmt.Stringer

	New() hash.Hash
}

func findHasher(name string) Hasher {
	for _, h := range hashers {
		if h.String() == name {
			return h
		}
	}
	return nil
}

// Hasher strategies
var (
	SHA256 Hasher = _sha256{}
	SHA512 Hasher = _sha512{}
)

var hashers = []Hasher{
	SHA256,
	SHA512,
}

type _sha256 struct{}

func (_sha256) String() string {
	return "sha256"
}

func (_sha256) New() hash.Hash {
	return sha256.New()
}

type _sha512 struct{}

func (_sha512) String() string {
	return "sha512"
}

func (_sha512) New() hash.Hash {
	return sha512.New()
}
