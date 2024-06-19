package secure_hardware_extension

import (
	"encoding/hex"
	"log"
)

var (
	KEY_UPDATE_ENC_C SheBytes = decodeHex("010153484500800000000000000000B0")
	KEY_UPDATE_MAC_C SheBytes = decodeHex("010253484500800000000000000000B0")
	DEBUG_KEY_C      SheBytes = decodeHex("010353484500800000000000000000B0")
	PRNG_KEY_C       SheBytes = decodeHex("010453484500800000000000000000B0")
	PRNG_SEED_KEY_C  SheBytes = decodeHex("010553484500800000000000000000B0")
	PRNG_EXTENSION_C SheBytes = decodeHex("80000000000000000000000000000100")
)

const (
	SECURITY_FLAG_WRITE_PROTECTION    SecurityFlags = 0x01 << 5
	SECURITY_FLAG_BOOT_PROTECTION     SecurityFlags = 0x01 << 4
	SECURITY_FLAG_DEBUGGER_PROTECTION SecurityFlags = 0x01 << 3
	SECURITY_FLAG_KEY_USAGE           SecurityFlags = 0x01 << 2
	SECURITY_FLAG_WILDCARD            SecurityFlags = 0x01 << 1
	SECURITY_FLAG_CMAC_USAGE          SecurityFlags = 0x01 << 0
)

const (
	SECRET_KEY = iota // iota 从 0 开始自增
	MASTER_ECU_KEY
	BOOT_MAC_KEY
	BOOT_MAC
	KEY_1
	KEY_2
	KEY_3
	KEY_4
	KEY_5
	KEY_6
	KEY_7
	KEY_8
	KEY_9
	KEY_10
	RAM_KEY
)

func decodeHex(s string) SheBytes {
	bytes, err := hex.DecodeString(s)
	if err != nil {
		log.Fatalf("failed to decode hex string: %v", err)
	}
	return bytes
}
