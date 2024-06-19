package secure_hardware_extension

import "encoding/hex"

// SheBytes is a type alias for []byte
type SheBytes []byte
type SecurityFlags uint8

func NewSheBytes(size int, value byte) SheBytes {

	bytes := make(SheBytes, size)
	for i := 0; i < size; i++ {
		bytes[i] = value
	}
	return bytes
}

func (s SheBytes) String() string {
	return hex.EncodeToString(s)
}
