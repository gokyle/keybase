package main

import (
	"flag"
	"fmt"
	"github.com/gokyle/keybase/api"
	"github.com/gokyle/readpass"
	"os"
)

func zero(in []byte) {
	for i := range in {
		in[i] ^= in[i]
	}
}

func login(username string) (session *api.Session, err error) {
	start, err := api.GetSalt(username)
	if err != nil {
		return
	}

	password, err := readpass.PasswordPromptBytes("keybase.io password: ")
	if err != nil {
		return
	}

	session, err = api.Login(username, password, start)
	zero(password)
	return
}

func main() {
	flUser := flag.String("u", "", "keybase.io username or email")
	flag.Parse()

	session, err := login(*flUser)
	if err != nil {
		fmt.Printf("Login failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Logged in as %s.\n", session.User.Basics.Username)
}
