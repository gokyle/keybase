package openpgp

import (
	"io/ioutil"
	"os"
	"testing"

	"golang.org/x/crypto/openpgp"
)

var (
	testPubRing     *KeyRing
	testSecRing     *KeyRing
	testPubRingPath = "testdata/pubring.gpg"
	testSecRingPath = "testdata/secring.gpg"
)

var testPubArmoured = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.14 (GNU/Linux)

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
Zoyl4vk5eA==
=H+lo
-----END PGP PUBLIC KEY BLOCK-----`

// TestLoadPubRing attempts to load the test public keyring in
// testdata/. This validates that a public key ring can be loaded. It
// also verifies that a public key ring is appropriately marked.
func TestLoadPubRing(t *testing.T) {
	var err error
	testPubRing, err = LoadKeyRing(testPubRingPath)
	if err != nil {
		t.Fatalf("%v", err)
	} else if testPubRing.private {
		t.Fatal("public keyring should not be private")
	}
}

// TestStorePubRing attempts to store the public keyring to a
// temporary file, which is removed once the test is complete. This
// validates that a key ring can be properly exported.
func TestStorePubRing(t *testing.T) {
	tempFile, err := ioutil.TempFile("testdata/", "openpgp_test")
	if err != nil {
		t.Fatalf("%v", err)
	}

	tfName := tempFile.Name()
	tempFile.Close()
	defer os.Remove(tfName)

	testPubRing.path = tfName
	err = testPubRing.Store()
	if err != nil {
		t.Fatalf("%v", err)
	}

	if len(testPubRing.Entities) < 1 {
		t.Fatal("no entities loaded")
	}

	tempKeyRing, err := LoadKeyRing(tfName)
	if err != nil {
		t.Fatalf("%v", err)
	} else if tempKeyRing.private {
		t.Fatal("exported key ring should be public")
	}

	if len(tempKeyRing.Entities) != len(testPubRing.Entities) {
		t.Fatal("the key ring was not fully exported")
	}

	for k, _ := range testPubRing.Entities {
		if _, ok := tempKeyRing.Entities[k]; !ok {
			t.Fatal("key in public key ring wasn't exported'")
		}
	}
}

// TestLoadSecRing validates loading secret keyrings.
func TestLoadSecRing(t *testing.T) {
	var err error
	testSecRing, err = LoadKeyRing(testSecRingPath)
	if err != nil {
		t.Fatalf("%v", err)
	} else if !testSecRing.private {
		t.Fatal("private keyring should be private")
	}
}

// TestStoreSecRing tests to ensure that attempting to store a secret
// keyring fails; this is due to a limitation in the Go openpgp
// package.
func TestStoreSecRing(t *testing.T) {
	tempFile, err := ioutil.TempFile("testdata/", "openpgp_test")
	if err != nil {
		t.Fatalf("%v", err)
	}

	tfName := tempFile.Name()
	tempFile.Close()
	defer os.Remove(tfName)

	testSecRing.path = tfName
	err = testSecRing.Store()
	if err != ErrSecStore {
		t.Fatal("secret keyring should not be exportable")
	}
}

// TestImportPub validates importing armoured public keys.
func TestImportPub(t *testing.T) {
	n, err := testPubRing.Import(testPubArmoured)
	if err != nil {
		t.Fatalf("%v", err)
	} else if n != 1 {
		t.Fatal("only one public key should be imported")
	}

}

// TestImportPubToSecFail checks to make sure attempting to import a
// public key to a secret keyring fails.
func TestImportPubToSecFail(t *testing.T) {
	_, err := testSecRing.Import(testPubArmoured)
	if err != ErrSecRing {
		t.Fatal("import of public key should fail in secret key ring")
	}
}

// TestExportPub checks to make sure that a public can be exported and
// re-imported.
func TestExportPub(t *testing.T) {
	var fpr = "1F72F8B9CF8D215881E3C1D0AF7DB9C0CCAFF8EB"
	armoured, err := testPubRing.Export(fpr)
	if err != nil {
		t.Fatalf("%v", err)
	}

	testPubRing.Entities = map[string]*openpgp.Entity{}
	if n, err := testPubRing.Import(armoured); err != nil {
		t.Fatalf("%v", err)
	} else if n != 1 {
		t.Fatal("failed to import public key")
	}

	armoured, err = testPubRing.Export("")
	if err != nil {
		t.Fatalf("%v", err)
	}

	testPubRing.Entities = map[string]*openpgp.Entity{}
	if n, err := testPubRing.Import(armoured); err != nil {
		t.Fatalf("%v", err)
	} else if n != 1 {
		t.Fatal("failed to import public key")
	}
}

// TestSign validates producing an armoured detached signature using a
// private key.
func TestSign(t *testing.T) {
	var passphrase = []byte("passphrase")
	var fpr = "1F72F8B9CF8D215881E3C1D0AF7DB9C0CCAFF8EB"

	signer := testSecRing.Entity(fpr)
	if signer == nil {
		t.Fatal("invalid secret keyring")
	} else if signer.PrivateKey == nil {
		t.Fatal("invalid secret key in secrey keyring")
	}

	err := signer.PrivateKey.Decrypt(passphrase)
	if err != nil {
		t.Fatalf("unlock failed: %v", err)
	} else if signer.PrivateKey.Encrypted {
		t.Fatal("failed to unlock key")
	}

	message := []byte("Hello, world")
	sig, err := testSecRing.Sign(message, fpr)
	if err != nil {
		t.Fatalf("signature failed: %v", err)
	} else if len(sig) == 0 {
		t.Fatal("empty signature")
	}
	ioutil.WriteFile("testdata/signature.asc", sig, 0644)
}
