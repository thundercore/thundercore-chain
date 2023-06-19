// msggroup is a package we define group of message type that would be exchange between host and those host subscriber
package msggroup

type Group uint8

// Messages are classified into these groups
const (
	NetworkMsg   = Group(0x00)
	ConsensusMsg = Group(0x10)
	ChainSyncMsg = Group(0x20)
	TxServiceMsg = Group(0x30)
	GroupMask    = Group(0xF0)
)

func GetMessageGroup(messageType uint8) Group {
	return GroupMask & Group(messageType)
}

func IsConsensusMessage(v uint8) bool {
	return GetMessageGroup(v) == ConsensusMsg
}

func IsChainSyncMessage(v uint8) bool {
	return GetMessageGroup(v) == ChainSyncMsg
}
