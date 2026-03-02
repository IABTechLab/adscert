package keyring

import (
	"time"
)

type KeyringManager struct {
	configList   *AdsCertCallSignConfigList
	keyGenerator KeyGenerator
}

func NewKeyringManager(configList *AdsCertCallSignConfigList, keyGenerator KeyGenerator) *KeyringManager {
	return &KeyringManager{
		configList:   configList,
		keyGenerator: keyGenerator,
	}
}

func (m *KeyringManager) AssignKeys() error {
	actionTimestamp := time.Now().UTC().Format(time.RFC3339)
	realms := m.configList.GetAllCallSignRealms()
	for _, r := range realms {
		if len(r.Keys) == 0 {
			keyConfig, err := m.makeNewKey(actionTimestamp)
			if err != nil {
				return err
			}
			r.Keys = append(r.Keys, keyConfig)
		}
	}
	return nil
}

func (m *KeyringManager) makeNewKey(actionTimestamp string) (*AdsCertKeyConfig, error) {
	keyConfig := &AdsCertKeyConfig{
		TimestampCreated: actionTimestamp,
	}
	if err := m.keyGenerator.GenerateKeysForConfig(keyConfig); err != nil {
		return nil, err
	}
	return keyConfig, nil
}
