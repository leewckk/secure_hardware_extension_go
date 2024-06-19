package secure_hardware_extension

import "fmt"

// MemoryUpdateInfo 类
type MemoryUpdateMessage struct {
	AuthKey SheBytes
	M1      SheBytes
	M2      SheBytes
}

// NewMemoryUpdateInfo 构造函数
func NewMemoryUpdateMessage(authKey, m1, m2 SheBytes) MemoryUpdateMessage {
	return MemoryUpdateMessage{
		AuthKey: authKey,
		M1:      m1,
		M2:      m2,
	}
}

func (m *MemoryUpdateMessage) String() string {

	return fmt.Sprintf("auth_key: %x, m1: %x, m2: %x",
		m.AuthKey, m.M1, m.M2)

}
