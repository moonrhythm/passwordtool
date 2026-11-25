package passwordtool

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
)

func TestPBKDF2DefaultIterationsFollowHasher(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		hc   PBKDF2
		iter int
	}{
		{name: "sha512", hc: PBKDF2{}, iter: pbkdf2DefaultIter},
		{name: "sha256", hc: PBKDF2{H: SHA256}, iter: pbkdf2SHA256Iter},
		{name: "sha1", hc: PBKDF2{H: SHA1}, iter: pbkdf2SHA1Iter},
		{name: "explicit", hc: PBKDF2{Iter: 4096, H: SHA256}, iter: 4096},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			hashed, err := tc.hc.Hash("superman")
			if err != nil {
				t.Fatal(err)
			}
			iter, salt, err := pbkdf2Parts(hashed)
			if err != nil {
				t.Fatal(err)
			}
			if iter != tc.iter {
				t.Fatalf("iterations = %d, want %d", iter, tc.iter)
			}
			if len(salt) != hashMinSaltLen {
				t.Fatalf("salt length = %d, want %d", len(salt), hashMinSaltLen)
			}
			if err := Compare(hashed, "superman"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestScryptDefaultIsOWASPFloor(t *testing.T) {
	t.Parallel()

	hashed, err := Scrypt{}.Hash("superman")
	if err != nil {
		t.Fatal(err)
	}
	n, salt, err := scryptParts(hashed)
	if err != nil {
		t.Fatal(err)
	}
	if n != scryptDefaultN {
		t.Fatalf("N = %d, want %d", n, scryptDefaultN)
	}
	if len(salt) != hashMinSaltLen {
		t.Fatalf("salt length = %d", len(salt))
	}
}

func TestHashRejectsShortSaltOrKey(t *testing.T) {
	t.Parallel()

	short := []struct {
		name string
		hash func() (string, error)
	}{
		{name: "argon2 salt", hash: func() (string, error) { return (Argon2id{S: hashMinSaltLen - 1}).Hash("superman") }},
		{name: "argon2 key", hash: func() (string, error) { return (Argon2id{KeyLen: hashMinKeyLen - 1}).Hash("superman") }},
		{name: "pbkdf2 salt", hash: func() (string, error) { return (PBKDF2{S: hashMinSaltLen - 1}).Hash("superman") }},
		{name: "pbkdf2 key", hash: func() (string, error) { return (PBKDF2{KeyLen: hashMinKeyLen - 1}).Hash("superman") }},
		{name: "scrypt salt", hash: func() (string, error) { return (Scrypt{S: hashMinSaltLen - 1}).Hash("superman") }},
		{name: "scrypt key", hash: func() (string, error) { return (Scrypt{K: hashMinKeyLen - 1}).Hash("superman") }},
	}
	for _, tc := range short {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := tc.hash(); err != ErrInvalidHash {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func pbkdf2Parts(hashed string) (int, []byte, error) {
	rest, ok := strings.CutPrefix(hashed, "pbkdf2$")
	if !ok {
		return 0, nil, ErrInvalidHash
	}
	xs := strings.Split(rest, "$")
	if len(xs) != 5 {
		return 0, nil, ErrInvalidHash
	}
	iter, err := strconv.Atoi(xs[1])
	if err != nil {
		return 0, nil, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(xs[3])
	if err != nil {
		return 0, nil, err
	}
	return iter, salt, nil
}

func scryptParts(hashed string) (int, []byte, error) {
	rest, ok := strings.CutPrefix(hashed, "scrypt$")
	if !ok {
		return 0, nil, ErrInvalidHash
	}
	xs := strings.Split(rest, "$")
	if len(xs) != 5 {
		return 0, nil, ErrInvalidHash
	}
	n, err := strconv.Atoi(xs[0])
	if err != nil {
		return 0, nil, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(xs[3])
	if err != nil {
		return 0, nil, err
	}
	return n, salt, nil
}
