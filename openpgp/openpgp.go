package openpgp

import (
	"code.google.com/p/go.crypto/openpgp"
	//"code.google.com/p/go.crypto/openpgp/packet"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

var DefaultPublicKeyRing = filepath.Join(os.Getenv("HOME"), ".gnupg", "pubring.gpg")
var DefaultSecretKeyRing = filepath.Join(os.Getenv("HOME"), ".gnupg", "secring.gpg")

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
	tempFile, err := ioutil.TempFile(filepath.Dir(keyRing.path), "openpgp")
	if err != nil {
		return
	}
	defer tempFile.Close()

	for _, e := range keyRing.Entities {
		if keyRing.private {
			err = e.SerializePrivate(tempFile, nil)
		} else {
			err = e.Serialize(tempFile)
		}
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
