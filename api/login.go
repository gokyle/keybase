package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

type loginRound1 struct {
	Status       *Status `json:"status"`
	GuestID      string  `json:"guest_id"`
	Salt         string  `json:"salt"`
	LoginSession string  `json:"login_session"`
	PWHVersion   int     `json:"pwh_version"`
	CSRFToken    string  `json:"csrf_token"`
}

type sessionStart struct {
	GuestID    []byte
	Salt       []byte
	Session    []byte
	PWHVersion int
	Token      string
}

func (s *sessionStart) Destroy() {
	if s == nil {
		return
	}
	zero(s.GuestID)
	zero(s.Salt)
	zero(s.Session)
}

func newSession(lr1 *loginRound1) (s *sessionStart, err error) {
	s = new(sessionStart)

	s.GuestID, err = hex.DecodeString(lr1.GuestID)
	if err != nil {
		s = nil
		return
	}

	s.Salt, err = hex.DecodeString(lr1.Salt)
	if err != nil {
		s = nil
		return
	}

	s.Session, err = base64.StdEncoding.DecodeString(lr1.LoginSession)
	if err != nil {
		s = nil
		return
	}

	s.PWHVersion = lr1.PWHVersion
	s.Token = lr1.CSRFToken
	return
}

// GetSalt retrieves a salt for the named user. It returns a session
// start, which should only be passed to Login.
func GetSalt(user string) (session *sessionStart, err error) {
	defer func() {
		if err != nil {
			session.Destroy()
		}
	}()
	url := fmt.Sprintf("%s/?email_or_username=%s", commandUrl("getsalt"), user)
	resp, err := http.Get(url)
	if err != nil {
		return
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	resp.Body.Close()

	lr1 := new(loginRound1)
	err = json.Unmarshal(body, lr1)
	if err != nil {
		return
	}
	if !lr1.Status.Success() {
		err = lr1.Status
		return
	}

	session, err = newSession(lr1)
	return
}

// Login completes a login after a call to GetSalt. The session start
// value is destroyed once the function exits.
func Login(user string, password []byte, sstart *sessionStart) (session *Session, err error) {
	defer sstart.Destroy()
	pwh, err := scryptPassphrase(password, sstart.Salt)
	if err != nil {
		return
	}
	pwh = pwh[192:224]
	pwhHMAC := hmacSHA512(pwh, sstart.Session)

	var form = url.Values{}
	form.Add("email_or_username", user)
	form.Add("hmac_pwh", fmt.Sprintf("%x", pwhHMAC))
	form.Add("login_session", base64.StdEncoding.EncodeToString(sstart.Session))
	form.Add("csrf_token", sstart.Token)

	resp, err := http.PostForm(commandUrl("login"), form)
	if err != nil {
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	resp.Body.Close()

	session = new(Session)
	err = json.Unmarshal(body, session)
	return
}
