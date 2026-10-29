package atrust

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Cookie is the persisted subset of an HTTP cookie needed to restore a
// session. The cookie jar also needs the host and scheme.
type Cookie struct {
	Host   string `json:"host"`
	Scheme string `json:"scheme"`
	Name   string `json:"name"`
	Value  string `json:"value"`
}

type persistedState struct {
	DeviceID       string          `json:"device_id"`
	SID            string          `json:"sid"`
	Cookies        []Cookie        `json:"cookies"`
	SignKey        string          `json:"sign_key"`
	Username       string          `json:"username,omitempty"`
	ServerManifest json.RawMessage `json:"server_manifest,omitempty"`
	Resources      json.RawMessage `json:"resources,omitempty"`
	VIP            string          `json:"vip,omitempty"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

func stateFilePath(dir string) string {
	if dir == "" {
		dir = "atrust"
	}
	return filepath.Join(dir, "state.json")
}

func loadState(path string) (*persistedState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &persistedState{}, nil
		}
		return nil, err
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse aTrust state %s: %w", path, err)
	}
	return &state, nil
}

func saveState(path string, state *persistedState) error {
	state.UpdatedAt = time.Now()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
