package openpgp

import (
	"io/ioutil"
	"os"
	"testing"
)

var (
	testPubRing     *KeyRing
	testSecRing     *KeyRing
	testPubRingPath = "testdata/pubring.gpg"
	testSecRingPath = "testdata/secring.gpg"
)

func TestLoadPubRing(t *testing.T) {
	var err error
	testPubRing, err = LoadKeyRing(testPubRingPath)
	if err != nil {
		t.Fatalf("%v", err)
	} else if testPubRing.private {
		t.Fatal("public keyring should not be private")
	}
}

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
}

func TestLoadSecRing(t *testing.T) {
	var err error
	testSecRing, err = LoadKeyRing(testSecRingPath)
	if err != nil {
		t.Fatalf("%v", err)
	} else if !testSecRing.private {
		t.Fatal("private keyring should be private")
	}
}

func TestStoreSecRing(t *testing.T) {
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
}
