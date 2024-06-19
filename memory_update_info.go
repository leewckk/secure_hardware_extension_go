package secure_hardware_extension

import (
	"errors"
	"fmt"
)

// MemoryUpdateInfo 类
type MemoryUpdateInfo struct {
	NewKey    SheBytes
	AuthKey   SheBytes
	NewKeyID  uint8
	AuthKeyID uint8
	Counter   uint32
	UID       SheBytes
	Flags     SecurityFlags
}

// NewMemoryUpdateInfo 构造函数
func NewMemoryUpdateInfo(newKey, authKey SheBytes, newKeyID, authKeyID uint8, counter uint32, uid SheBytes, flags SecurityFlags) *MemoryUpdateInfo {
	return &MemoryUpdateInfo{
		NewKey:    newKey,
		AuthKey:   authKey,
		NewKeyID:  newKeyID,
		AuthKeyID: authKeyID,
		Counter:   counter,
		UID:       uid,
		Flags:     flags,
	}
}

func NewMemoryUpdateInfoFromMessage(msg *MemoryUpdateMessage) (*MemoryUpdateInfo, error) {

	if nil == msg {
		return nil, errors.New("invalid paramter , nullptr")
	}

	m1 := msg.M1
	m2 := msg.M2
	authKey := msg.AuthKey

	uid := m1[0:15]
	authKeyId := m1[15] & 0x0F
	newKeyId := (m1[15] & 0xF0) >> 4

	k1, err := MiyaguchiPreneel(authKey, KEY_UPDATE_ENC_C)
	if nil != err {
		return nil, err
	}

	iv := make(SheBytes, 16)
	m2Plain, err := DecryptAesCBC(k1, m2, iv)
	if nil != err {
		return nil, err
	}

	var counter uint32 = (uint32(m2Plain[0]) << 24) |
		(uint32(m2Plain[1]) << 16) |
		(uint32(m2Plain[2]) << 8) |
		(uint32(m2Plain[3])&0xF0)>>4

	fid := ((m2Plain[3] & 0x0F) << 2) | ((m2Plain[4] & 0xC0) >> 6)
	newKey := m2Plain[16:]

	return NewMemoryUpdateInfo(newKey, authKey, uint8(newKeyId), uint8(authKeyId), uint32(counter), uid, SecurityFlags(fid)), nil
}

func (m MemoryUpdateInfo) String() string {

	return fmt.Sprintf("new_key_id: 0x%02x, new_key : %s, \r\nauth_id: 0x%02x, auth_key: %s, \r\ncounter: %d, uid : %s, \r\nflags: %x",
		m.NewKeyID, m.NewKey, m.AuthKeyID, m.AuthKey, m.Counter, m.UID, m.Flags)

}
