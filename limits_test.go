package passwordtool

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestCompareAcceptsPreviousDefaultHashes(t *testing.T) {
	t.Parallel()

	// Hashes of "superman" produced by the defaults before the cost ceiling.
	hashes := []string{
		"argon2id$2$65536$4$16$BqjLoPKTUFyy+T1VuNhIIQ$pvCdJvGGp+QeLPIy8troHw",
		"pbkdf2$sha512$10000$32$uSuXiY8NCr4$FCbY/FyLZnKmmrBdMVye51a9dHEjpo96YZ2hHuzAc+M",
		"scrypt$32768$8$1$GvYAX/FwPRvW5inslpXO/A$etj8FlW4GJr7+eyMSayy7HrnRlA+NaHZfSLsuZQw/kY",
		"bcrypt$$2a$10$p5IxPCaoFBUzv5S2U7vas.CS.lQNvCzwb0YIjdGKAsiyN2iXQgpYu",
		"bcrypt-hash$sha256$$2a$10$jfPc8qfVpUh5Wd6nUIyIRu7EGWdDCvz27jfsy3b0iw1mNriBLXfxy",
	}
	for _, hashed := range hashes {
		if err := Compare(hashed, "superman"); err != nil {
			t.Fatalf("Compare(%s): %v", hashed, err)
		}
		if err := Compare(hashed, "lex"); err != ErrMismatched {
			t.Fatalf("Compare wrong password: %v", err)
		}
	}
}

func TestCompareRejectsParametersThatPanicOrMismatch(t *testing.T) {
	t.Parallel()

	salt16 := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
	salt8 := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 8))
	salt7 := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 7))
	key16 := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 16))
	key15 := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 15))
	key32 := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))

	cases := []string{
		fmt.Sprintf("argon2id$0$65536$4$16$%s$%s", salt16, key16),
		fmt.Sprintf("argon2id$2$65536$0$16$%s$%s", salt16, key16),
		fmt.Sprintf("argon2id$2$65536$4$0$%s$%s", salt16, key16),
		fmt.Sprintf("argon2id$2$0$1$16$%s$%s", salt16, key16),
		fmt.Sprintf("argon2id$%d$65536$4$16$%s$%s", argon2idMaxTime+1, salt16, key16),
		fmt.Sprintf("argon2id$2$65536$4$16$%s$%s", salt7, key16),
		fmt.Sprintf("argon2id$2$65536$4$16$%s$%s", salt16, key15),
		fmt.Sprintf("argon2id$2$65536$4$16$***$%s", key16),
		fmt.Sprintf("pbkdf2$sha512$0$32$%s$%s", salt8, key32),
		fmt.Sprintf("pbkdf2$sha512$-1$32$%s$%s", salt8, key32),
		fmt.Sprintf("pbkdf2$sha512$10000$0$%s$%s", salt8, key32),
		fmt.Sprintf("pbkdf2$sha512$10000$-1$%s$%s", salt8, key32),
		fmt.Sprintf("pbkdf2$sha512$10000$32$%s$%s", salt7, key32),
		fmt.Sprintf("pbkdf2$sha512$10000$32$%s$%s", salt8, key16),
		fmt.Sprintf("pbkdf2$nope$10000$32$%s$%s", salt8, key32),
		fmt.Sprintf("scrypt$1$8$1$%s$%s", salt16, key32),
		fmt.Sprintf("scrypt$3$8$1$%s$%s", salt16, key32),
		fmt.Sprintf("scrypt$32768$0$1$%s$%s", salt16, key32),
		fmt.Sprintf("scrypt$-2$8$1$%s$%s", salt16, key32),
		fmt.Sprintf("scrypt$32768$8$1$%s$%s", salt7, key32),
		fmt.Sprintf("argon2id$2$65536$4$16$%s$%s", strings.Repeat("A", 500), key16),
	}
	for _, hashed := range cases {
		if err := Compare(hashed, "superman"); err != ErrInvalidHash {
			t.Fatalf("Compare(%s) = %v", hashed, err)
		}
	}

	// Eight-byte salts are the historical PBKDF2 default and must still run the KDF.
	eight := fmt.Sprintf("argon2id$1$32$1$16$%s$%s", salt8, key16)
	if err := Compare(eight, "superman"); err != ErrMismatched {
		t.Fatalf("8-byte salt: %v", err)
	}
}

func TestHashRejectsParametersAboveCeiling(t *testing.T) {
	t.Parallel()

	if _, err := (Argon2id{Time: argon2idMaxTime + 1}).Hash("superman"); err != ErrInvalidHash {
		t.Fatalf("argon2 time: %v", err)
	}
	if _, err := (Argon2id{S: maxSaltLen + 1}).Hash("superman"); err != ErrInvalidHash {
		t.Fatalf("argon2 salt: %v", err)
	}
	if _, err := (Argon2id{KeyLen: maxKeyLen + 1}).Hash("superman"); err != ErrInvalidHash {
		t.Fatalf("argon2 key: %v", err)
	}
	if _, err := (PBKDF2{S: minSaltLen - 1}).Hash("superman"); err != ErrInvalidHash {
		t.Fatalf("pbkdf2 salt: %v", err)
	}
	if _, err := (Scrypt{N: 3}).Hash("superman"); err != ErrInvalidHash {
		t.Fatalf("scrypt N: %v", err)
	}
	if err := checkArgon2id(argon2idMaxTime, argon2idMaxMemory, 1, maxKeyLen); err != nil {
		t.Fatal(err)
	}
	// N=2^20 fits the memory cap only for a small r. r=8 at that N is 1 GiB.
	if err := checkScryptParams(scryptMaxN, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := checkScryptParams(1<<18, 8, 1); err != nil {
		t.Fatal(err)
	}
}

func TestHashAndCompareRejectUnboundedParameters(t *testing.T) {
	if os.Getenv("PASSWORDTOOL_BOUNDED") == "1" {
		salt16 := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
		key16 := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 16))
		key32 := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
		checks := []error{
			Compare(fmt.Sprintf("argon2id$2$%d$4$16$%s$%s", argon2idMaxMemory+1, salt16, key16), "superman"),
			firstErr((Argon2id{Memory: argon2idMaxMemory + 1}).Hash("superman")),
			Compare("bcrypt$$2a$31$"+strings.Repeat(".", 53), "superman"),
			firstErr((Bcrypt{Cost: bcryptMaxCost + 1}).Hash("superman")),
			Compare(fmt.Sprintf("scrypt$%d$8$1$%s$%s", scryptMaxN*2, salt16, key32), "superman"),
			firstErr((Scrypt{N: scryptMaxN * 2, R: 8, P: 1}).Hash("superman")),
			Compare(fmt.Sprintf("pbkdf2$sha512$%d$32$%s$%s", pbkdf2MaxIter+1, base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 8)), key32), "superman"),
			firstErr((PBKDF2{Iter: pbkdf2MaxIter + 1}).Hash("superman")),
		}
		for _, err := range checks {
			if err != ErrInvalidHash {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		os.Exit(0)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHashAndCompareRejectUnboundedParameters$")
	cmd.Env = append(os.Environ(), "PASSWORDTOOL_BOUNDED=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("unbounded parameters: %v\n%s", err, out)
	}
}

func firstErr(v string, err error) error {
	return err
}
