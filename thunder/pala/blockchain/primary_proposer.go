package blockchain

// epoch 1 will map to proposers[0]
var PrimaryProposerIndexer = func(epoch Epoch, numProps uint32) uint32 {
	return (epoch.E - 1) % uint32(numProps)
}
