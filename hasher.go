package passwordtool

import (
	"crypto/sha256"
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

var (
	SHA256 Hasher = _sha256{}
)

var hashers = []Hasher{
	SHA256,
}

type _sha256 struct{}

func (_sha256) String() string {
	return "sha256"
}

func (_sha256) New() hash.Hash {
	return sha256.New()
}
