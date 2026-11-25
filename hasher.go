package passwordtool

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"slices"
)

// Hasher type
type Hasher interface {
	fmt.Stringer

	New() hash.Hash
}

func findHasher(name string) Hasher {
	i := slices.IndexFunc(hashers, func(h Hasher) bool {
		return h.String() == name
	})
	if i < 0 {
		return nil
	}
	return hashers[i]
}

// Hasher strategies
var (
	SHA512 Hasher = _sha512{}
	SHA256 Hasher = _sha256{}
	SHA1   Hasher = _sha1{}
)

var hashers = []Hasher{
	SHA512,
	SHA256,
	SHA1,
}

type _sha1 struct{}

func (_sha1) String() string {
	return "sha1"
}

func (_sha1) New() hash.Hash {
	return sha1.New()
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
