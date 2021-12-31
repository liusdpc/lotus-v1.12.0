package sealing

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/filecoin-project/specs-storage/storage"

	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/lotus/extern/sector-storage/stores"

	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var PwdKey = []byte("0000000000000000") //16,24,32, AES-128,AES-192,AES-256
var NeedKey = false

func PKCS7UnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	if length == 0 {
		//return nil, errors.New("PKCS7UnPadding errors")
		return nil, errors.New("PKCS7UnPadding errors")
	} else {
		unpadding := int(origData[length-1])
		return origData[:(length - unpadding)], nil
	}
}

func AesDeCrypt(cypted []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(cypted))
	blockMode.CryptBlocks(origData, cypted)
	origData, err = PKCS7UnPadding(origData)
	if err != nil {
		return nil, err
	}
	return origData, err
}

func DePwdCode(pwd string) ([]byte, error) {
	pwdByte, err := base64.StdEncoding.DecodeString(pwd)
	if err != nil {
		return nil, err
	}
	return AesDeCrypt(pwdByte, PwdKey)
}

func (m *Sealing) PledgeSector(ctx context.Context) (storage.SectorRef, error) {
	if NeedKey {
		// ------------------ Check FIL_FILGUARD_KEY start
		amid, err := address.IDFromAddress(m.maddr)
		if err != nil {
			return storage.SectorRef{}, xerrors.Errorf("address.IDFromAddress(m.maddr): %w", err)
		}
		mid := abi.ActorID(amid)

		var pwdkey string
		minerPath, ok := os.LookupEnv("LOTUS_MINER_PATH")
		if ok {
			mb, errIgnore := ioutil.ReadFile(filepath.Join(minerPath, "externalWorker.json"))
			if errIgnore == nil {
				var meta stores.TestSchedulerMeta
				if errIgnore := json.Unmarshal(mb, &meta); errIgnore == nil {
					pwdkey = meta.FiLGuardKey
				}
			}
		}
		if pwdkey == "" {
			pwdkey, ok = os.LookupEnv("FIL_FILGUARD_KEY")
			if !ok {
				return storage.SectorRef{}, xerrors.Errorf("Your authorization Key FIL_FILGUARD_KEY is not found, please contact FilGuard filguard.io!")
			}
		}
		if pwdkey == "" {
			return storage.SectorRef{}, xerrors.Errorf("Your authorization Key FIL_FILGUARD_KEY is not found, please contact FilGuard filguard.io!")
		}
		bytes, err := DePwdCode(pwdkey)
		if err != nil {
			return storage.SectorRef{}, xerrors.Errorf("Your authorization Key FIL_FILGUARD_KEY explanation is wrong, please contact FilGuard filguard.io: %w", err)
		}
		key := string(bytes) //"086151_2021-02-20"
		var minerId string
		var endDate string
		if i := strings.Index(key, "_"); i >= 0 {
			minerId = key[:i]
			endDate = key[i+1:]
		}

		if minerId != "000000" && minerId != mid.String() && minerId != "0"+mid.String() && minerId != "f0"+mid.String() && minerId != "t0"+mid.String() {
			return storage.SectorRef{}, xerrors.Errorf("Your authorization key FIL_FILGUARD_KEY MinerID %s is incorrect, expected MinerID %d, please contact FilGuard filguard.io!", minerId, mid)
		}
		//localTime, err := time.Parse("2021-01-02", endDate)
		localTime, err := time.ParseInLocation("2006-01-02", endDate, time.Local)
		if err != nil {
			return storage.SectorRef{}, xerrors.Errorf("The expiration date %s of your authorization key FIL_FILGUARD_KEY is incorrect, please contact FilGuard filguard.io: %w", endDate, err)
		}

		if time.Now().Unix() > localTime.Unix() {
			return storage.SectorRef{}, xerrors.Errorf("Your authorization key FIL_FILGUARD_KEY endDate %s has expired, please contact FilGuard filguard.io!", endDate)
		}
		// ------------------ Check FIL_FILGUARD_KEY end
	}

	m.startupWait.Wait()

	m.inputLk.Lock()
	defer m.inputLk.Unlock()

	cfg, err := m.getConfig()
	if err != nil {
		return storage.SectorRef{}, xerrors.Errorf("getting config: %w", err)
	}

	if cfg.MaxSealingSectors > 0 {
		if m.stats.curSealing() >= cfg.MaxSealingSectors {
			return storage.SectorRef{}, xerrors.Errorf("too many sectors sealing (curSealing: %d, max: %d)", m.stats.curSealing(), cfg.MaxSealingSectors)
		}
	}

	spt, err := m.currentSealProof(ctx)
	if err != nil {
		return storage.SectorRef{}, xerrors.Errorf("getting seal proof type: %w", err)
	}

	sid, err := m.createSector(ctx, cfg, spt)
	if err != nil {
		return storage.SectorRef{}, err
	}

	log.Infof("Creating CC sector %d", sid)
	return m.minerSector(spt, sid), m.sectors.Send(uint64(sid), SectorStartCC{
		ID:         sid,
		SectorType: spt,
	})
}
