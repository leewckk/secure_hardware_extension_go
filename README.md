

## Secure Hardware Extension



This is a implementation of AUTOSAR Secure Hardware Extension.

Features:

* Generate M1 ~ M5 from some key values
* Parse M1 M2 Memory update protocol messages in order to get the update information.



## Environment



`golang` 1.18 or later



## Examples



````go
package main

import (
	"fmt"

	"github.com/google/uuid"
	SHE "github.com/leewckk/secure_hardware_extension_go"
)

type SecureConfig struct {
	NewKeyId  uint8
	NewKey    SHE.SheBytes
	AuthKeyId uint8
	AuthKey   SHE.SheBytes
	UID       SHE.SheBytes
	Flags     SHE.SecurityFlags
	Counter   uint32
}

func NewSecureConfig(
	newKeyId uint8,
	newKey SHE.SheBytes,
	authKeyId uint8,
	authKey SHE.SheBytes,
	uid SHE.SheBytes,
	flags SHE.SecurityFlags,
	counter uint32) SecureConfig {

	return SecureConfig{
		NewKeyId:  newKeyId,
		NewKey:    newKey,
		AuthKeyId: authKeyId,
		AuthKey:   authKey,
		UID:       uid,
		Flags:     flags,
		Counter:   counter,
	}
}

func NewUUID() SHE.SheBytes {
	id := uuid.New()
	byteArray := id[:15]
	return byteArray
}

func main() {

	// testBytes := SHE.NewSheBytes(16, 0xCC)
	// fmt.Printf("%s\r\n", testBytes)

	infoList := make([]SHE.MemoryUpdateInfo, 0)

	infoList = append(infoList, *SHE.NewMemoryUpdateInfo(SHE.NewSheBytes(16, 0x00), SHE.NewSheBytes(16, 0x00), SHE.MASTER_ECU_KEY, SHE.MASTER_ECU_KEY, 1, SHE.NewSheBytes(15, 0x00), 0x00))
	infoList = append(infoList, *SHE.NewMemoryUpdateInfo(SHE.NewSheBytes(16, 0xCC), SHE.NewSheBytes(16, 0x00), SHE.BOOT_MAC_KEY, SHE.MASTER_ECU_KEY, 1, SHE.NewSheBytes(15, 0x00), 0x00))
	infoList = append(infoList, *SHE.NewMemoryUpdateInfo(SHE.NewSheBytes(16, 0xCC), SHE.NewSheBytes(16, 0x00), SHE.BOOT_MAC, SHE.MASTER_ECU_KEY, 1, SHE.NewSheBytes(15, 0x00), 0x00))
	infoList = append(infoList, *SHE.NewMemoryUpdateInfo(SHE.NewSheBytes(16, 0x11), SHE.NewSheBytes(16, 0x00), SHE.KEY_1, SHE.MASTER_ECU_KEY, 1, SHE.NewSheBytes(15, 0x00), 0x00))
	infoList = append(infoList, *SHE.NewMemoryUpdateInfo(SHE.NewSheBytes(16, 0x22), SHE.NewSheBytes(16, 0x00), SHE.KEY_2, SHE.MASTER_ECU_KEY, 1, SHE.NewSheBytes(15, 0x00), 0x00))
	infoList = append(infoList, *SHE.NewMemoryUpdateInfo(SHE.NewSheBytes(16, 0x33), SHE.NewSheBytes(16, 0x00), SHE.KEY_3, SHE.MASTER_ECU_KEY, 1, SHE.NewSheBytes(15, 0x00), 0x00))
	infoList = append(infoList, *SHE.NewMemoryUpdateInfo(SHE.NewSheBytes(16, 0x44), SHE.NewSheBytes(16, 0x00), SHE.KEY_4, SHE.MASTER_ECU_KEY, 1, SHE.NewSheBytes(15, 0x00), 0x00))
	infoList = append(infoList, *SHE.NewMemoryUpdateInfo(SHE.NewSheBytes(16, 0x55), SHE.NewSheBytes(16, 0x00), SHE.KEY_5, SHE.MASTER_ECU_KEY, 1, SHE.NewSheBytes(15, 0x00), 0x00))
	infoList = append(infoList, *SHE.NewMemoryUpdateInfo(SHE.NewSheBytes(16, 0x66), SHE.NewSheBytes(16, 0x00), SHE.KEY_6, SHE.MASTER_ECU_KEY, 1, SHE.NewSheBytes(15, 0x00), 0x00))
	infoList = append(infoList, *SHE.NewMemoryUpdateInfo(SHE.NewSheBytes(16, 0x66), SHE.NewSheBytes(16, 0x00), SHE.KEY_7, SHE.MASTER_ECU_KEY, 1, NewUUID(), 0x00))

	for _, config := range infoList {

		fmt.Println("###############################################################")
		fmt.Printf("\r\norigin key info: \r\n%s\r\n", config)

		protocol := SHE.NewMemoryUpdateProtocol(&config)
		fmt.Printf("%s", protocol)

		m1, _ := protocol.GetM1()
		m2, _ := protocol.GetM2()
		message := SHE.NewMemoryUpdateMessage(protocol.Info.AuthKey, m1, m2)

		info, _ := SHE.NewMemoryUpdateInfoFromMessage(&message)
		fmt.Printf("decode result: \r\n%s\r\n", *info)
	}
}

````





the test program is in [test_main.go](https://github.com/leewckk/secure_hardware_extension_go/blob/main/testProg/test_main.go)

