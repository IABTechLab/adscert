package keyring

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

func CreateNewKeyringFile() (*AdsCertCallSignConfigList, error) {
	f, err := os.Open("adscertkeyring.json")
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
	}
	if f != nil {
		err = f.Close()
		if err != nil {
			return nil, fmt.Errorf("unable to close file: %v", err)
		}
		return nil, errors.New("file already exists")
	}

	config := &AdsCertCallSignConfigList{}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, err
	}

	if err = os.WriteFile("adscertkeyring.json", data, 0644); err != nil {
		return nil, err
	}

	return config, nil
}

func OverwriteKeyringFile(config *AdsCertCallSignConfigList) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	f, err := os.OpenFile("adscertkeyring.json", os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	_, err = f.Write(data)
	if err1 := f.Close(); err1 != nil && err == nil {
		err = err1
	}
	return err
}

func ReadKeyringFile() (*AdsCertCallSignConfigList, error) {
	data, err := os.ReadFile("adscertkeyring.json")
	if err != nil {
		return nil, err
	}
	config := &AdsCertCallSignConfigList{}
	if err = json.Unmarshal(data, config); err != nil {
		return nil, err
	}
	return config, nil
}
