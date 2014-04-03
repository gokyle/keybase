package api

import "flag"
import "testing"
import "fmt"

var testConfig struct {
	LoginUser string
	LoginPass []byte
	Start     *sessionStart
}

var testSession *Session

func init() {
	lUser := flag.String("api.user", "alice", "test user")
	lPass := flag.String("api.pass", "password", "Read the password from the console.")
	flag.Parse()

	testConfig.LoginUser = *lUser
	testConfig.LoginPass = []byte(*lPass)
}

func TestGetSalt(t *testing.T) {
	var err error
	testConfig.Start, err = GetSalt(testConfig.LoginUser)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if testConfig.Start == nil {
		t.Fatalf("get salt failed")
	}
}

func TestLogin(t *testing.T) {
	var err error
	testSession, err = Login(testConfig.LoginUser, testConfig.LoginPass, testConfig.Start)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestNextSequenceNo(t *testing.T) {
	if testSession == nil {
		t.Fatal("session not established")
	}
	seqNum, err := testSession.NextSequence()
	if err != nil {
		t.Fatalf("%v", err)
	}
	fmt.Printf("seq num: %d\n", seqNum)
}
