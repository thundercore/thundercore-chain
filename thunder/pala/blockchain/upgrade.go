package blockchain

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/ethdb"
)

const v1 = "1.0"

var upgradeLogger = logger.NewChildLgr("upgrader")

func Upgrade(db ethdb.Database, bc *core.BlockChain) error {
	// this function can change when we need another schema change
	v, err := readSchemaVersion(db)
	if err == nil && v == v1 {
		upgradeLogger.Info("Already in current version(%s)", v1)
		return nil
	}

	upgradeLogger.Info("+++ Begin to upgrade storage to PaLa(%s)", v1)
	currentBlock := bc.CurrentBlock()
	h := currentBlock.Number()

	for bc.Config().Thunder.IsPala(h) {
		upgradeLogger.Info("Current height %d is higher than pala ", h)
		h.Sub(h, common.Big1)
	}

	if h.Cmp(currentBlock.Number()) != 0 {
		upgradeLogger.Warn("Rewinding blockchain back to %d", h)
		err := bc.SetHead(h.Uint64())
		if err != nil {
			upgradeLogger.Critical("Cannot upgrade to Pala")
		}
	}

	sn := newBlock(bc.CurrentBlock(), bc.Config().Thunder).GetBlockSn()
	upgradeLogger.Info("Write finalized Block Sn and Freshest Nota Sn to %s", sn)

	batch := db.NewBatch()
	if err := writeFinalizeBlockSn(batch, sn); err != nil {
		return err
	}
	if err := writeFreshestNotarization(batch, sn); err != nil {
		return err
	}
	if err := writeSchemaVersion(batch, v1); err != nil {
		return err
	}
	if err := batch.Write(); err != nil {
		return err
	}

	upgradeLogger.Info("+++ Upgraded storage to PaLa(%s)", v1)

	return nil
}
