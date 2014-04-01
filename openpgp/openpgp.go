package openpgp

import (
	"code.google.com/p/go.crypto/openpgp"
	//"code.google.com/p/go.crypto/openpgp/packet"
	"bytes"
	"code.google.com/p/go.crypto/openpgp/armor"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

const Version = "0.1.0"

var (
	DefaultPublicKeyRing = filepath.Join(os.Getenv("HOME"), ".gnupg", "pubring.gpg")

	DefaultSecretKeyRing = filepath.Join(os.Getenv("HOME"), ".gnupg", "secring.gpg")
)

var (
	ErrPubRing     = errors.New("openpgp: public keyring")
	ErrSecRing     = errors.New("openpgp: secret keyring")
	ErrSecStore    = errors.New("openpgp: exporting secret keyring isn't supported'")
	ErrKeyNotFound = errors.New("openpgp: key not found")
)

// Paths to the public and secret keyrings.
var (
	PubRingPath string = DefaultPublicKeyRing
	SecRingPath string = DefaultSecretKeyRing
)

// A KeyRing contains a list of entities and the state required to
// maintain the key ring.
type KeyRing struct {
	Entities map[string]*openpgp.Entity
	path     string
	private  bool
}

// Private returns true if the keyring contains secret key material.
func (keyRing *KeyRing) Private() bool {
	return keyRing.private
}

// LoadKeyRing reads the unarmoured keyring stored at the named path.
func LoadKeyRing(path string) (keyRing *KeyRing, err error) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	el, err := openpgp.ReadKeyRing(file)
	if err != nil {
		return
	}

	keyRing = new(KeyRing)
	keyRing.path = path
	keyRing.Entities = map[string]*openpgp.Entity{}
	for _, e := range el {
		if e.PrivateKey != nil {
			keyRing.private = true
		}
		id := fmt.Sprintf("%x", e.PrimaryKey.Fingerprint)
		keyRing.Entities[id] = e
	}
	return
}

// Store writes the keyring to disk as an unarmoured keyring.
func (keyRing *KeyRing) Store() (err error) {
	if keyRing.private {
		err = ErrSecStore
		return
	}
	tempFile, err := ioutil.TempFile(filepath.Dir(keyRing.path), "openpgp")
	if err != nil {
		return
	}
	defer tempFile.Close()

	for _, e := range keyRing.Entities {
		err = e.Serialize(tempFile)
		if err != nil {
			tempFile.Close()
			os.Remove(tempFile.Name())
			return
		}
	}
	tempFile.Close()
	err = os.Rename(tempFile.Name(), keyRing.path)
	if err != nil {
		os.Remove(tempFile.Name())
	}
	return
}

// Import imports an armoured public key block.
func (keyRing *KeyRing) Import(armoured string) (n int, err error) {
	buf := bytes.NewBufferString(armoured)
	el, err := openpgp.ReadArmoredKeyRing(buf)
	if err != nil {
		return
	}

	for _, e := range el {
		if keyRing.private && e.PrivateKey == nil {
			err = ErrSecRing
			return
		} else if !keyRing.private && e.PrivateKey != nil {
			err = ErrPubRing
			return
		}
	}

	for _, e := range el {
		id := fmt.Sprintf("%x", e.PrimaryKey.Fingerprint)
		if _, ok := keyRing.Entities[id]; !ok {
			keyRing.Entities[id] = e
			n++
		}
	}
	return
}

// Export writes out the named public key, or all public keys if keyID
// is empty. The result is an ASCII-armoured public key.
func (keyRing *KeyRing) Export(keyID string) (armoured string, err error) {
	buf := new(bytes.Buffer)
	blockType := "PGP PUBLIC KEY BLOCK"
	blockHeaders := map[string]string{
		"Version": fmt.Sprintf("Keybase Go client (OpenPGP version %s)", Version),
	}

	armourBuffer, err := armor.Encode(buf, blockType, blockHeaders)
	if err != nil {
		return
	}

	if keyID != "" {
		e, ok := keyRing.Entities[strings.ToLower(keyID)]
		if !ok {
			err = ErrKeyNotFound
			return
		}
		e.Serialize(armourBuffer)
	} else {
		if len(keyRing.Entities) == 0 {
			err = ErrKeyNotFound
			return
		}
		for _, e := range keyRing.Entities {
			e.Serialize(armourBuffer)
		}
	}

	armourBuffer.Close()

	armoured = string(buf.Bytes())
	return
}
