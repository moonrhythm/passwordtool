# passwordtool

[![GoDoc](https://godoc.org/github.com/moonrhythm/passwordtool?status.svg)](https://godoc.org/github.com/moonrhythm/passwordtool)

passwordtool hashes passwords and checks them later. Each hash string starts with an algorithm name and stores the parameters and salt that produced it. `Compare` reads that prefix, so a caller can verify a password without remembering which algorithm created the hash.

`Hash` uses Argon2id. The same password hashes to a different string each call because the salt comes from `crypto/rand`.

## Install

Go 1.26 or later.

```
go get github.com/moonrhythm/passwordtool
```

## Hash and compare

```go
package main

import (
	"fmt"
	"log"

	"github.com/moonrhythm/passwordtool"
)

func main() {
	hashed, err := passwordtool.Hash("superman")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hashed) // argon2id$2$65536$4$16$<salt>$<key>

	err = passwordtool.Compare(hashed, "superman")
	if err == nil {
		fmt.Println("match")
	}

	err = passwordtool.Compare(hashed, "lex")
	if err == passwordtool.ErrMismatched {
		fmt.Println("wrong password")
	}
}
```

`Compare` returns three kinds of results:

| Result | Meaning |
| --- | --- |
| `nil` | The password matches. |
| `ErrMismatched` | The hash decoded, and the password does not match. |
| `ErrInvalidHash` | The string is empty, names an unknown algorithm, or cannot be decoded. |

bcrypt and scrypt can also return their own parameter errors unchanged.

## Algorithms

Every algorithm implements `HashComparer`: `String`, `Hash`, and `Compare`. A numeric field set to `0` or below, and a nil `Hasher`, uses the default when hashing. `Compare` uses the parameters stored in the hash string.

| Type | Prefix | Defaults |
| --- | --- | --- |
| `Argon2id` | `argon2id` | time 2, memory 65536 KiB (64 MiB), threads 4, key length 16 bytes, salt 16 bytes |
| `PBKDF2` | `pbkdf2` | SHA-512, 10000 iterations, key length 32 bytes, salt 8 bytes |
| `Scrypt` | `scrypt` | N 32768, r 8, p 1, key length 32 bytes, salt 16 bytes |
| `Bcrypt` | `bcrypt` | cost `bcrypt.DefaultCost` (10) |
| `BcryptHash` | `bcrypt-hash` | SHA-256, then bcrypt at the default cost |

`PBKDF2` and `BcryptHash` accept `SHA512`, `SHA256`, or `SHA1`. The name stored in the hash is `sha512`, `sha256`, or `sha1`.

Salt and derived keys are unpadded standard base64, except the bcrypt payload, which is a normal bcrypt hash.

```
argon2id$2$65536$4$16$<salt>$<key>
pbkdf2$sha512$10000$32$<salt>$<key>
scrypt$32768$8$1$<salt>$<key>
bcrypt$$2a$10$<bcrypt salt and hash>
bcrypt-hash$sha256$$2a$10$<bcrypt salt and hash>
```

`bcrypt` and `bcrypt-hash` contain `$$` because the bcrypt encoding itself starts with `$`.

## Argon2id

```go
hc := passwordtool.Argon2id{
	Time:    3,
	Memory:  64 * 1024, // KiB
	Threads: 4,
	KeyLen:  32,
	S:       16,
}

hashed, err := hc.Hash("superman")
if err != nil {
	log.Fatal(err)
}

// The package function reads the prefix and the stored parameters.
if err := passwordtool.Compare(hashed, "superman"); err != nil {
	log.Fatal(err)
}
```

`Time`, `Memory`, `Threads`, and `KeyLen` are the values passed to `argon2.IDKey`. `Memory` is KiB.

## PBKDF2

```go
hc := passwordtool.PBKDF2{
	Iter:   200_000,
	KeyLen: 32,
	S:      16,
	H:      passwordtool.SHA256,
}

hashed, err := hc.Hash("superman")
if err != nil {
	log.Fatal(err)
}
// pbkdf2$sha256$200000$32$<salt>$<key>

if err := passwordtool.Compare(hashed, "superman"); err != nil {
	log.Fatal(err)
}
```

## scrypt

`N` must be a power of two greater than 1. `Hash` returns the error from `scrypt.Key` when the parameters are rejected.

```go
hc := passwordtool.Scrypt{
	N: 32768,
	R: 8,
	P: 1,
	S: 16,
	K: 32,
}

hashed, err := hc.Hash("superman")
if err != nil {
	log.Fatal(err)
}

if err := hc.Compare(hashed, "superman"); err != nil {
	log.Fatal(err)
}
```

The key length is not a separate field in the string. `Compare` uses the length of the decoded key.

## bcrypt

```go
hc := passwordtool.Bcrypt{Cost: 12}

hashed, err := hc.Hash("superman")
if err != nil {
	log.Fatal(err)
}
// bcrypt$$2a$12$<bcrypt salt and hash>

err = passwordtool.Compare(hashed, "lex")
if err == passwordtool.ErrMismatched {
	fmt.Println("wrong password")
}
```

Cost must be from 4 to 31. `0` selects `bcrypt.DefaultCost`. The cost used for a hash is the cost inside the bcrypt payload.

## bcrypt-hash

`BcryptHash` hashes the password with SHA-256, SHA-512, or SHA-1, then bcrypts that digest. The digest is shorter than bcrypt's 72-byte password limit.

```go
hc := passwordtool.BcryptHash{
	Bcrypt: passwordtool.Bcrypt{Cost: 12},
	H:      passwordtool.SHA512,
}

hashed, err := hc.Hash("superman")
if err != nil {
	log.Fatal(err)
}
// bcrypt-hash$sha512$$2a$12$<bcrypt salt and hash>

if err := passwordtool.Compare(hashed, "superman"); err != nil {
	log.Fatal(err)
}
```

A nil `H` stores `sha256`.

## License

MIT
