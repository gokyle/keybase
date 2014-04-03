package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/gokyle/keybase/api"
	"github.com/gokyle/keybase/openpgp"
	"github.com/gokyle/readpass"
	"io/ioutil"
	"os"
	"strings"
	"time"
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

const displayTime = "2006-01-02 15:04 MST"

func unixToString(ts int) string {
	t := time.Unix(int64(ts), 0)
	return t.Format(displayTime)
}

func lookup(name string) {
	user, err := api.LookupUser(name)
	if err != nil {
		fmt.Printf("Lookup failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Details for user %s:\n", user.Basics.Username)
	fmt.Printf("\tCreated: %s\n", unixToString(user.Basics.Created))
	fmt.Printf("\tLast modified: %s\n", unixToString(user.Basics.Modified))
	fmt.Printf("\tProfile:\n")
	fmt.Printf("\t\tLast updated: %s\n", unixToString(user.Profile.Modified))
	fmt.Printf("\t\tFull name: %s\n", user.Profile.FullName)
	fmt.Printf("\t\tLocation: %s\n", user.Profile.Location)
	fmt.Printf("\t\tBio:\n")
	fmt.Printf("\t\t\t%s\n", user.Profile.Bio) // TODO(kyle): wordwrap bio

	if pub, ok := user.PublicKeys["primary"]; ok {
		fmt.Printf("\tPublic key\n")
		fmt.Printf("\t\tKey ID: %s\n", pub.KeyID)
		fmt.Printf("\t\tCreated: %s\n", unixToString(pub.Created))
		fmt.Printf("\t\tLast modified: %s\n", unixToString(pub.Modified))
	} else {
		fmt.Printf("\tNo public key.\n")
	}

}

func fetchKey(name, outFile string) {
	user, err := api.LookupUser(name)
	if err != nil {
		fmt.Printf("Fetch failed: %v\n", err)
		os.Exit(1)
	}

	pub, ok := user.PublicKeys["primary"]
	if !ok || pub.Bundle == "" {
		fmt.Printf("%s hasn't uploaded a public key yet.")
		os.Exit(1)
	}

	if outFile != "-" {
		err = ioutil.WriteFile(outFile, []byte(pub.Bundle+"\n"), 0644)
		if err != nil {
			fmt.Printf("Couldn't write %s's public key to disk: %v\n", user.Basics.Username, err)
		} else {
			fmt.Printf("Wrote %s's public key to %s.\n'", user.Basics.Username, outFile)
		}
	} else {
		fmt.Fprintf(os.Stdout, "%s\n", pub.Bundle)
	}
}

func deleteKey(session *api.Session) {
	pub, ok := session.User.PublicKeys["primary"]
	if !ok {
		fmt.Println("There is no public key to delete.")
		os.Exit(1)
	}
	err := session.DeleteKey(pub.KeyID)
	if err != nil {
		fmt.Printf("Failed to delete your public key: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Your public key has been deleted from your account.")
}

func postAuth(session *api.Session, keyRing *openpgp.KeyRing) {
	pub := session.User.PublicKeys["primary"]
	if pub == nil {
		fmt.Println("No public key for this account.")
		os.Exit(1)
	}

	fmt.Printf("Fingerprint: %s\n", pub.Fingerprint)
	signer := keyRing.Entity(pub.Fingerprint)
	if signer == nil {
		fmt.Println("No private key for this account.")
		os.Exit(1)
	}

	/*
	   	var signature = `-----BEGIN PGP MESSAGE-----
	   Version: Keybase Go client (OpenPGP version 0.1.0)

	   xA0DAAIB7k+6hRB9rTcBrQFRYgBTPJCXeyJib2R5Ijp7ImtleSI6eyJmaW5nZXJw
	   cmludCI6IjNiMGM0ZGU3ZDE2NThkMWE1ZmFlYzEyMGVlNGZiYTg1MTA3ZGFkMzci
	   LCJob3N0Ijoia2V5YmFzZS5pbyIsImtleV9pZCI6IjAxMDEwYjA0YTFmNzk2M2Nm
	   YjUxNjQ0ZWUyM2E0YTA2NmY1MzkxN2FmNzE1N2E5Njg5MWViYjAzNTExZTU1Yjk2
	   MmUzMGEiLCJ1aWQiOiI5NGVmMWUzNTc4OWM2ZmE2NThiNzhlMWIwNWVlZGUwMCIs
	   InVzZXJuYW1lIjoia2lzb20ifSwic3RyaW5nIjoiIiwidHlwZSI6ImF1dGgiLCJ2
	   ZXJzaW9uIjoxfSwiY3RpbWUiOjEzOTY0NzgwOTQsImV4cGlyZXNfaW4iOjg2NDAw
	   LCJ0YWciOiJzaWduYXR1cmUifcLBXAQAAQIAEAUCUzyQlwkQ7k+6hRB9rTcAANSz
	   EAAseFDy8srABjWmQqp4uhaOPGUDzO9E2wYWm6GcFf60KeenMkYUCssHoP12a4eB
	   ZLgt2ERkIFAQmn+hQkkfBSK7tQjh6XQmXstHwkhUp2XG2/Kn3Lek7t2sgaqzdt46
	   /qVmgymBbSgraW0JYzDC+Bta8RRfYhkYyNTjtWnx9Ue2r2R6UcTDGyTS4cWMgAVY
	   h1ZgQwNLfHMDqjEP93gPj9n8JZb5EN0MXGCe3Z6wMfXIams2QQ4TdsMGvwJffKel
	   GGOaqUYoTlE01zSF9RA53xTzqwC7PpVcOO6V7FMpRM6UQE6x1MQzy/Iz8gBZONpb
	   G24IkbpFj+SQYdUJ3fedTUiTWT32n/9sgp3NKY4lFdYKEDhv6fMgSLFkMhbvf6YC
	   d0Jd1OORtzke3MxJPDHRLlnCNdNA3ZfwD1Dx2Mu8j7JknWBdUsZK2KtDh3hijfmY
	   TGT1TL6fBT9DAzGfJj305rTNaYR2GnD8ncmqMCD5O+ePVFaQxyrC9zgy50UEOTNS
	   BLVqFj1mCE38ziBxO39Y1Kx4U0ZUmQ90Fz7nzhw3alnPQaPF6M8f+q2Mx+xuZhHF
	   hYddlV4afpsHp14sAeLaImLZ+IPvL+KH0f3Pc0N9rSaCJhsR5yLLpoPXk3RXrs+1
	   kXBuzD8AyhGVVJ+VCOuauUwRQT+Ergl7auG94uQi7SN15w==
	   =gRI/
	   -----END PGP MESSAGE-----`
	*/
	sigData, err := session.SignaturePostAuthData()
	if err != nil {
		fmt.Printf("Failed to get signature post auth data: %v\n", err)
		os.Exit(1)
	}

	signature, err := keyRing.Sign(sigData, pub.Fingerprint)
	if err != nil {
		fmt.Printf("Signing failed: %v\n", err)
		os.Exit(1)
	}

	authToken, err := session.SignaturePostAuth([]byte(signature))
	if err != nil {
		fmt.Printf("Posting signature authentication failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Authentication token: %x\n", authToken)
}

func validCommands() {
	fmt.Println("Valid commands:")
	fmt.Printf("\tlookup <users...>\n")
	fmt.Printf("\tfetch <user>\n")
	fmt.Printf("\ttestlogin\n")
	fmt.Printf("\tupload\n")
	fmt.Printf("\tdelete\n")
}

func main() {
	flUser := flag.String("u", "", "keybase.io username or email")
	flKeyFile := flag.String("pub", "", "public key file")
	flOutFile := flag.String("out", "", "output file")
	flGPGDir := flag.String("home", "", "override the default GnuPG home directory")
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Println("No command specified.")
		validCommands()
		os.Exit(1)
	}

	if *flGPGDir != "" {
		openpgp.SetKeyRingDir(*flGPGDir)
	}

	cmd := flag.Arg(0)
	switch cmd {
	case "lookup":
		if flag.NArg() < 2 {
			fmt.Println("You didn't specify a user to lookup.'")
			os.Exit(1)
		}

		for _, name := range flag.Args()[1:] {
			lookup(name)
		}
	case "fetch":
		if flag.NArg() < 2 {
			fmt.Println("You didn't specify the user whose key you want to fetch.'")
			os.Exit(1)
		} else if flag.NArg() > 2 {
			fmt.Println("Only one user's key may be fetched at a time.'")
			os.Exit(1)
		}

		name := flag.Arg(1)
		outFile := *flOutFile
		if outFile == "" {
			outFile = name + ".pub"
		}
		fetchKey(name, outFile)
	case "testlogin":
		session, err := login(*flUser)
		if err != nil {
			fmt.Printf("Login failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Logged in as %s.\n", session.User.Basics.Username)
		fmt.Printf("Session token: %s\n", session.Session)
		fmt.Printf("CSRF token: %s\n", session.Token)
	case "upload":
		var armoured string
		var err error

		pubRing, err := openpgp.LoadKeyRing(openpgp.PubRingPath)
		if err != nil {
			fmt.Printf("Couldn't open public keyring: %v\n", err)
			os.Exit(1)
		}

		if *flKeyFile == "" {
			if flag.NArg() == 2 {
				armoured, err = pubRing.Export(flag.Arg(1))
				if err != nil {
					fmt.Printf("Key not found.")
					os.Exit(1)
				}
			} else {
				fmt.Println("No file specified (with -pub) and no fingerprint specified.")
				fmt.Println("Cowardly refusing to proceed.")
				os.Exit(1)
			}
		} else {

			pub, err := ioutil.ReadFile(*flKeyFile)
			if err != nil {
				fmt.Printf("Failed to read the public key: %v\n", err)
				os.Exit(1)
			}
			armoured = string(pub)
		}

		session, err := login(*flUser)
		if err != nil {
			fmt.Printf("Login failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Logged in as %s.\n", session.User.Basics.Username)

		kid, err := session.AddKey(armoured)
		if err != nil {
			fmt.Printf("Upload failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Successfully uploaded new key with ID %s.\n", kid)
	case "delete":
		session, err := login(*flUser)
		if err != nil {
			fmt.Printf("Login failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Logged in as %s.\n", session.User.Basics.Username)

		deleteKey(session)

	case "auth":
		secRing, err := openpgp.LoadKeyRing(openpgp.SecRingPath)
		if err != nil {
			fmt.Printf("Failed to load GnuPG secret keyring: %v.\n", err)
			os.Exit(1)
		}

		session, err := login(*flUser)
		if err != nil {
			fmt.Printf("Login failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Logged in as %s.\n", session.User.Basics.Username)
		postAuth(session, secRing)
	case "genkey":
		if *flOutFile == "" {
			fmt.Println("Please specify an output file with -out.")
			os.Exit(1)
		}
		newKey(*flOutFile)

	case "nextseq":
		session, err := login(*flUser)
		if err != nil {
			fmt.Printf("Login failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Logged in as %s.\n", session.User.Basics.Username)
		nextSeq(session)
	case "authtwit":
		secRing, err := openpgp.LoadKeyRing(openpgp.SecRingPath)
		if err != nil {
			fmt.Printf("Failed to load GnuPG secret keyring: %v.\n", err)
			os.Exit(1)
		}

		session, err := login(*flUser)
		if err != nil {
			fmt.Printf("Login failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Logged in as %s.\n", session.User.Basics.Username)
		authTwitter(session, secRing)
	}
}

func readPrompt(prompt string) (in string, err error) {
	fmt.Printf("%s", prompt)
	rd := bufio.NewReader(os.Stdin)
	line, err := rd.ReadString('\n')
	if err != nil {
		return
	}
	in = strings.TrimSpace(line)
	return
}

func newKey(outFile string) {
	name, err := readPrompt("Name: ")
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	} else if name == "" {
		fmt.Println("Name required!")
		os.Exit(1)
	}

	email, err := readPrompt("Email: ")
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	} else if email == "" {
		fmt.Println("Email required!")
		os.Exit(1)
	}

	_, err = openpgp.NewEntity(name, email, outFile)
	if err != nil {
		fmt.Printf("Failed to generate key: %v\n", err)
		os.Exit(1)
	}
}

func nextSeq(session *api.Session) {
	seqNum, prev, err := session.NextSequence()
	if err != nil {
		fmt.Printf("[!] %v\n", err)
		os.Exit(1)
	} else {
		fmt.Printf("Next sequence: %d\n", seqNum)
		fmt.Printf("Previous hash: %s\n", prev)
	}
}

func authTwitter(session *api.Session, keyRing *openpgp.KeyRing) {
	username, err := readPrompt("Twitter username: ")
	if err != nil {
		fmt.Printf("Couldn't read from console: %v\n", err)
	}

	authData, err := session.TwitterGetAuth(username)
	if err != nil {
		fmt.Printf("Couldn't get authentication data: %v\n", err)
	}

	pub := session.User.PublicKeys["primary"]
	if pub == nil {
		fmt.Println("No public key for this account.")
		os.Exit(1)
	}

	fmt.Printf("Fingerprint: %s\n", pub.Fingerprint)
	signer := keyRing.Entity(pub.Fingerprint)
	if signer == nil {
		fmt.Println("No private key for this account.")
		os.Exit(1)
	}

	ioutil.WriteFile("/tmp/authdata.json", authData, 0644)
	sig, err := keyRing.Sign(authData, pub.Fingerprint)
	if err != nil {
		fmt.Printf("Couldn't sign authentication data: %v\n", err)
		os.Exit(1)
	}

	proof, err := session.ServicePostAuth(sig, username, "twitter")
	if err != nil {
		fmt.Printf("Couldn't authenticate via Twitter: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Proof text: '%s'\n", proof.Text)
}
