package openpgp

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"code.google.com/p/go.crypto/openpgp/packet"
	"crypto"
	"crypto/sha1"
	_ "crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/gokyle/readpass"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const Version = "0.1.0"

var (
	DefaultPublicKeyRing = filepath.Join(os.Getenv("HOME"), ".gnupg", "pubring.gpg")
	DefaultSecretKeyRing = filepath.Join(os.Getenv("HOME"), ".gnupg", "secring.gpg")
)

func SetKeyRingDir(dir string) {
	PubRingPath = filepath.Join(dir, "pubring.gpg")
	SecRingPath = filepath.Join(dir, "secring.gpg")
}

var (
	ErrPubRing          = errors.New("openpgp: public keyring")
	ErrSecRing          = errors.New("openpgp: secret keyring")
	ErrSecStore         = errors.New("openpgp: exporting secret keyring isn't supported'")
	ErrKeyNotFound      = errors.New("openpgp: key not found")
	ErrInvalidPublicKey = errors.New("openpgp: invalid public key")
)

// Paths to the public and secret keyrings.
var (
	PubRingPath string = DefaultPublicKeyRing
	SecRingPath string = DefaultSecretKeyRing
)

// SaneDefaultConfig is a more secure default config than the defaults.
func ParanoidDefaultConfig() *packet.Config {
	return &packet.Config{
		DefaultHash:            crypto.SHA384,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig:      &packet.CompressionConfig{-1},
	}
}

var DefaultConfig *packet.Config = nil

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

func (keyRing *KeyRing) Entity(keyID string) (e *openpgp.Entity) {
	return keyRing.Entities[strings.ToLower(keyID)]
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

		for name, id := range e.Identities {
			err = e.PrimaryKey.VerifyUserIdSignature(name, id.SelfSignature)
			if err != nil {
				return
			}
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
	blockType := openpgp.PublicKeyType
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

// Unlock decrypts the secured key, reading the passphrase from the
// command line.
func (keyRing *KeyRing) Unlock(keyID string) (err error) {
	e, ok := keyRing.Entities[strings.ToLower(keyID)]
	if !ok || e.PrivateKey == nil {
		err = ErrKeyNotFound
		return
	}

	if !e.PrivateKey.Encrypted {
		return
	}

	var id string
	for k, _ := range e.Identities {
		id = k
		break
	}
	prompt := fmt.Sprintf(`Please enter the passphrase for the key:
    %s
    %x
Enter passphrase: `, id, e.PrimaryKey.KeyId)
	passphrase, err := readpass.PasswordPromptBytes(prompt)
	if err != nil {
		return
	}

	err = e.PrivateKey.Decrypt(passphrase)
	return
}

// Sign signs the given message.
func (keyRing *KeyRing) Sign(message []byte, keyID string) (sig []byte, err error) {
	err = keyRing.Unlock(keyID)
	if err != nil {
		return
	}

	signer := keyRing.Entities[strings.ToLower(keyID)]
	buf := new(bytes.Buffer)
	hdr := map[string]string{
		"Version": fmt.Sprintf("Keybase Go client (OpenPGP version %s)", Version),
	}
	armourBuf, err := armor.Encode(buf, "PGP MESSAGE", hdr)
	if err != nil {
		return
	}

	opSig := &packet.OnePassSignature{
		SigType:    packet.SigTypeBinary,
		Hash:       crypto.SHA1,
		PubKeyAlgo: packet.PubKeyAlgoRSA,
		KeyId:      signer.PrimaryKey.KeyId,
		IsLast:     true,
	}
	err = opSig.Serialize(armourBuf)
	if err != nil {
		return
	}

	literalPacket, err := newLiteralDataPacket(message, "", uint32(time.Now().Unix()))
	if err != nil {
		return
	}
	_, err = armourBuf.Write(literalPacket)
	if err != nil {
		return
	}

	sigPacket := &packet.Signature{
		SigType:      packet.SigTypeBinary,
		IssuerKeyId:  &signer.PrimaryKey.KeyId,
		PubKeyAlgo:   packet.PubKeyAlgoRSA,
		Hash:         crypto.SHA1,
		CreationTime: time.Now(),
	}
	h := sha1.New()
	h.Write(message)
	err = sigPacket.Sign(h, signer.PrivateKey, nil)
	if err != nil {
		return
	}

	err = sigPacket.Serialize(armourBuf)
	if err != nil {
		return
	}
	armourBuf.Close()
	sig = buf.Bytes()
	return
}

// NewEntity creates a new entity. It doesn't provide an option for comments.
func NewEntity(name, email, outFile string) (ne *openpgp.Entity, err error) {
	ne, err = openpgp.NewEntity(name, "", email, DefaultConfig)
	if err != nil {
		return
	}

	out, err := os.Create(outFile)
	if err != nil {
		ne = nil
		return
	}

	hdr := map[string]string{
		"Version": fmt.Sprintf("Keybase Go client (OpenPGP version %s)", Version),
	}

	keyOut, err := armor.Encode(out, openpgp.PrivateKeyType, hdr)
	if err != nil {
		ne = nil
		return
	}

	defer func() {
		keyOut.Close()
		out.Close()
	}()

	err = ne.SerializePrivate(keyOut, DefaultConfig)
	if err != nil {
		ne = nil
		return
	}

	return
}

func newLiteralDataPacket(literal []byte, fileName string, ts uint32) (pkt []byte, err error) {
	var header = [3]byte{0x80}
	header[0] |= (11 << 2)
	header[0] |= 1

	var timeStamp = uint32(time.Now().Unix())
	var timeStampBytes [4]byte
	binary.BigEndian.PutUint32(timeStampBytes[:], timeStamp)
	if err != nil {
		return
	}

	body := []byte("b")
	body = append(body, byte(len(fileName)))
	body = append(body, []byte(fileName)...)
	body = append(body, timeStampBytes[:]...)
	body = append(body, literal...)
	binary.BigEndian.PutUint16(header[1:], uint16(len(body)))
	if err != nil {
		return
	}
	buf := new(bytes.Buffer)
	buf.Write(header[:])
	buf.Write(body)
	pkt = buf.Bytes()
	return
}
