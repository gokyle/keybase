package main

import (
	"flag"
	"fmt"
	"github.com/gokyle/keybase/api"
	"github.com/gokyle/readpass"
	"io/ioutil"
	"os"
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

func validCommands() {
	fmt.Println("Valid commands:")
	fmt.Printf("\tlookup <users...>\n")
	fmt.Printf("\tfetch <user>\n")
	fmt.Printf("\ttestlogin\n")
}

func main() {
	flUser := flag.String("u", "", "keybase.io username or email")
	flOutFile := flag.String("out", "", "output file")
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Println("No command specified.")
		validCommands()
		os.Exit(1)
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

	}
}
