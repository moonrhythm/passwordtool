package passwordtool

// Ceilings applied before a KDF runs. Compare rejects a stored hash outside
// these limits. Hash enforces the same ceilings, plus hashMinSaltLen and
// hashMinKeyLen, so every hash this package creates can still be verified.
const (
	argon2idMaxTime   = 16
	argon2idMaxMemory = 256 << 10 // KiB; 256 MiB

	pbkdf2MaxIter = 5_000_000

	scryptMaxN   = 1 << 20
	scryptMaxR   = 32
	scryptMaxP   = 16
	scryptMaxMem = 256 << 20 // bytes

	bcryptMaxCost = 16

	minSaltLen = 8
	maxSaltLen = 64
	maxKeyLen  = 128

	// New hashes use a 16-byte salt and tag. Compare still accepts the
	// 8-byte salt stored by older PBKDF2 defaults.
	hashMinSaltLen = 16
	hashMinKeyLen  = 16
)

func checkArgon2id(time, memory uint32, threads uint8, keyLen uint32) error {
	if time < 1 || time > argon2idMaxTime ||
		threads < 1 ||
		memory < 1 || memory > argon2idMaxMemory ||
		keyLen < 1 || keyLen > maxKeyLen {
		return ErrInvalidHash
	}
	return nil
}

func checkPBKDF2(iter, keyLen int) error {
	if iter < 1 || iter > pbkdf2MaxIter || keyLen < 1 || keyLen > maxKeyLen {
		return ErrInvalidHash
	}
	return nil
}

func checkScryptParams(n, r, p int) error {
	if n <= 1 || n > scryptMaxN || n&(n-1) != 0 ||
		r < 1 || r > scryptMaxR ||
		p < 1 || p > scryptMaxP {
		return ErrInvalidHash
	}
	// 128*N*r bytes, the size of the scrypt mixing buffer.
	if uint64(n) > scryptMaxMem/(128*uint64(r)) {
		return ErrInvalidHash
	}
	return nil
}

func checkKeyLen(n int) error {
	if n < 1 || n > maxKeyLen {
		return ErrInvalidHash
	}
	return nil
}

func checkSaltLen(n int) error {
	if n < minSaltLen || n > maxSaltLen {
		return ErrInvalidHash
	}
	return nil
}

func checkHashSizes(saltLen, keyLen int) error {
	if saltLen < hashMinSaltLen || keyLen < hashMinKeyLen {
		return ErrInvalidHash
	}
	return nil
}
