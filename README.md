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

Parameters outside the [limits](#parameter-limits) are `ErrInvalidHash`. bcrypt can still return its own error when the bcrypt payload is malformed.

## Algorithms

Every algorithm implements `HashComparer`: `String`, `Hash`, and `Compare`. A numeric field set to `0` or below, and a nil `Hasher`, uses the default when hashing. `Compare` uses the parameters stored in the hash string.

| Type | Prefix | Defaults |
| --- | --- | --- |
| `Argon2id` | `argon2id` | time 2, memory 65536 KiB (64 MiB), threads 4, key length 16 bytes, salt 16 bytes |
| `PBKDF2` | `pbkdf2` | SHA-512 and 220000 iterations, SHA-256 and 600000 iterations, or SHA-1 and 1400000 iterations; key length 32 bytes, salt 16 bytes |
| `Scrypt` | `scrypt` | N 131072, r 8, p 1, key length 32 bytes, salt 16 bytes |
| `Bcrypt` | `bcrypt` | cost `bcrypt.DefaultCost` (10) |
| `BcryptHash` | `bcrypt-hash` | SHA-256, then bcrypt at the default cost |

`PBKDF2` and `BcryptHash` accept `SHA512`, `SHA256`, or `SHA1`. The name stored in the hash is `sha512`, `sha256`, or `sha1`.

Salt and derived keys are unpadded standard base64, except the bcrypt payload, which is a normal bcrypt hash.

```
argon2id$2$65536$4$16$<salt>$<key>
pbkdf2$sha512$220000$32$<salt>$<key>
scrypt$131072$8$1$<salt>$<key>
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
	Iter:   600_000,
	KeyLen: 32,
	S:      16,
	H:      passwordtool.SHA256,
}

hashed, err := hc.Hash("superman")
if err != nil {
	log.Fatal(err)
}
// pbkdf2$sha256$600000$32$<salt>$<key>

if err := passwordtool.Compare(hashed, "superman"); err != nil {
	log.Fatal(err)
}
```

## scrypt

`N` must be a power of two from 2 to 1048576, and `128*N*r` must be at most 256 MiB. Parameters outside the [limits](#parameter-limits) return `ErrInvalidHash`.

```go
hc := passwordtool.Scrypt{
	N: 131072,
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

Cost must be from 4 to 16. `0` selects `bcrypt.DefaultCost`. `Compare` reads the cost inside the bcrypt payload and rejects a cost above 16.

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

## Parameter limits

`Compare` reads the parameters from the hash string, checks them before the KDF runs, and returns `ErrInvalidHash` when a value is outside these bounds.

| Algorithm | What Compare accepts |
| --- | --- |
| Argon2id | time 1–16, memory 1–262144 KiB (256 MiB), at least 1 thread, key length 1–128 bytes, salt 8–64 bytes |
| PBKDF2 | 1–5000000 iterations, key length 1–128 bytes, salt 8–64 bytes |
| scrypt | `N` a power of two from 2 to 1048576, `r` 1–32, `p` 1–16, `128*N*r` at most 256 MiB, key length 1–128 bytes, salt 8–64 bytes |
| bcrypt | cost 4–16 |

The decoded key must be the same length as the key length stored in the hash. Salt and key bytes that are not unpadded standard base64 are `ErrInvalidHash`. Argon2 does not see a time, thread count, or key length of 0. bcrypt does not run its cost loop when the cost is above 16.

`Hash` uses those same ceilings. It also rejects an explicit salt or key length below 16 bytes, so the table's lower edge is what `Compare` still accepts, not what `Hash` will create. `0` selects the default, and every default salt and key is at least 16 bytes. An 8-byte salt still verifies because older PBKDF2 hashes used one.

A zero `PBKDF2.Iter` uses 220000 for SHA-512, 600000 for SHA-256, and 1400000 for SHA-1. An explicit `Iter` is stored as given.

## License

MIT
