package secure_hardware_extension

import (
	"fmt"
	"log"
	"slices"
)

type MemoryUpdateProtocol struct {
	Info *MemoryUpdateInfo
}

func NewMemoryUpdateProtocol(info *MemoryUpdateInfo) *MemoryUpdateProtocol {
	return &MemoryUpdateProtocol{
		Info: info,
	}
}

func NewMemoryUpdateProtocolFromMessage(msg *MemoryUpdateMessage) *MemoryUpdateProtocol {
	info, err := NewMemoryUpdateInfoFromMessage(msg)
	if nil != err {
		log.Fatal(err)
		return nil
	}
	return NewMemoryUpdateProtocol(info)
}

func (proto *MemoryUpdateProtocol) GetK1() (SheBytes, error) {
	return MiyaguchiPreneel(proto.Info.AuthKey, KEY_UPDATE_ENC_C)
}

func (proto *MemoryUpdateProtocol) GetK2() (SheBytes, error) {
	return MiyaguchiPreneel(proto.Info.AuthKey, KEY_UPDATE_MAC_C)
}

func (proto *MemoryUpdateProtocol) GetK3() (SheBytes, error) {
	return MiyaguchiPreneel(proto.Info.NewKey, KEY_UPDATE_ENC_C)
}

func (proto *MemoryUpdateProtocol) GetK4() (SheBytes, error) {
	return MiyaguchiPreneel(proto.Info.NewKey, KEY_UPDATE_MAC_C)
}

func (proto *MemoryUpdateProtocol) GetM1() (SheBytes, error) {
	// make a copy
	m1 := slices.Clone(proto.Info.UID)
	m1 = append(m1, (byte(proto.Info.NewKeyID<<4 | proto.Info.AuthKeyID&0x0F)))
	return m1, nil
}

func (proto *MemoryUpdateProtocol) GetM2() (SheBytes, error) {

	counter := proto.Info.Counter
	flag := proto.Info.Flags
	m2Plain := make(SheBytes, 16)
	iv := make(SheBytes, 16)

	counter = counter << 4
	m2Plain[0] = byte((counter >> 24) & 0xFF)
	m2Plain[1] = byte((counter >> 16) & 0xFF)
	m2Plain[2] = byte((counter >> 8) & 0xFF)
	m2Plain[3] = byte(uint8(counter&0xFF) | uint8((flag>>2)&0xF0))
	m2Plain[4] = byte(uint8((flag << 6) & 0xC0))

	m2Plain = append(m2Plain, proto.Info.NewKey...)
	k1, err := proto.GetK1()

	if nil != err {
		return nil, err
	}
	return EncryptAesCBC(k1, m2Plain, iv)
}

func (proto *MemoryUpdateProtocol) GetM3() (SheBytes, error) {

	m1, err1 := proto.GetM1()
	if nil != err1 {
		return nil, err1
	}

	m2, err2 := proto.GetM2()
	if nil != err2 {
		return nil, err2
	}

	m3Plain := append(m1, m2...)
	k2, err := proto.GetK2()
	if nil != err {
		return nil, err
	}

	return CmacAES(k2, m3Plain)
}

func (proto *MemoryUpdateProtocol) GetM4() (SheBytes, error) {

	counter := proto.Info.Counter
	plain := make(SheBytes, 16)

	counter = counter << 4
	plain[0] = byte((counter >> 24) & 0xFF)
	plain[1] = byte((counter >> 16) & 0xFF)
	plain[2] = byte((counter >> 8) & 0xFF)
	plain[3] = byte(uint8(counter&0xFF) | uint8(0x01<<3))

	k3, err := proto.GetK3()
	if nil != err {
		return nil, err
	}

	m4, err := EncryptAesECB(k3, plain)
	if nil != err {
		return nil, err
	}

	m1, err := proto.GetM1()
	if nil != err {
		return nil, err
	}

	m1 = append(m1, m4...)
	return m1, nil
}

func (proto *MemoryUpdateProtocol) GetM5() (SheBytes, error) {

	k4, err := proto.GetK4()

	if nil != err {
		return nil, err
	}

	m4, err := proto.GetM4()

	if nil != err {
		return nil, err
	}

	return CmacAES(k4, m4)
}

func (proto MemoryUpdateProtocol) String() string {

	m1, _ := proto.GetM1()
	m2, _ := proto.GetM2()
	m3, _ := proto.GetM3()
	m4, _ := proto.GetM4()
	m5, _ := proto.GetM5()

	return fmt.Sprintf("\r\nkey id: %d\r\nm1: %s \r\nm2: %s \r\nm3: %s\r\nm4: %s\r\nm5: %s\r\n", proto.Info.NewKeyID, m1, m2, m3, m4, m5)
}
