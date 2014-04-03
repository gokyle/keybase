package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

var ErrNoPublicKey = fmt.Errorf("api: no public key for user")

func commandUrl(cmd string) string {
	return "https://keybase.io/_/api/1.0/" + cmd + ".json"
}

// IsAPIError returns true if the error is from the Keybase API (and
// not a network / JSON / etc error).
func IsAPIError(err error) bool {
	switch err.(type) {
	case *Status:
		return true
	default:
		return false
	}
}

// Status contains the API call status results from keybase.io.
type Status struct {
	Desc string `json:"desc"`
	Code int    `json:"code"`
	Name string `json:"name"`
}

func (st *Status) Error() string {
	return fmt.Sprintf("%d: %s", st.Code, st.Desc)
}

// Success returns true if the call succeeded.
func (st *Status) Success() bool {
	if st.Code == 0 && st.Name == "OK" {
		return true
	}
	return false
}

// Session contains a keybase session, with user information.
type Session struct {
	Status  *Status `json:"status"`
	GuestID string  `json:"guest_id"`
	Session string  `json:"session"`
	UID     string  `json:"uid"`
	User    User    `json:"me"`
	Token   string  `json:"csrf_token"`
}

// LookupUser returns available user information for the named user.
func LookupUser(user string) (u *User, err error) {
	url := commandUrl("user/lookup") + "?username=" + user
	resp, err := http.Get(url)
	if err != nil {
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	resp.Body.Close()

	var userResponse struct {
		Status  *Status `json:"status"`
		Session string  `json:"session"`
		User    *User   `json:"them"`
	}

	err = json.Unmarshal(body, &userResponse)
	if err != nil {
		return
	} else if !userResponse.Status.Success() {
		err = userResponse.Status
		return
	}
	ioutil.WriteFile("/tmp/user.json", body, 0644)

	u = userResponse.User
	return
}

type keyResponse struct {
	Status  *Status `json:"status"`
	KeyID   string  `json:"kid"`
	Token   string  `json:"csrf_token"`
	Primary bool    `json:"is_primary"`
}

// AddKey adds a new public key to the account. This will replace any
// existing accounts.
func (s *Session) AddKey(pub string) (kid string, err error) {
	var form = url.Values{}
	form.Add("csrf_token", s.Token)
	form.Add("public_key", pub)
	form.Add("is_primary", "true")
	form.Add("session", s.Session)
	resp, err := http.PostForm(commandUrl("key/add"), form)
	if err != nil {
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	resp.Body.Close()

	var kr keyResponse
	err = json.Unmarshal(body, &kr)
	if err != nil {
		return
	} else if !kr.Status.Success() {
		err = kr.Status
		return
	}

	s.Token = kr.Token
	kid = kr.KeyID
	return
}

// DeleteKey performs a simple delete "revocation" (in Keybase
// parlance): it will delete the key with the named key ID from the
// user's account.
func (s *Session) DeleteKey(kid string) (err error) {
	var form = url.Values{}
	form.Add("csrf_token", s.Token)
	form.Add("kid", kid)
	form.Add("revocation_type", "0")
	form.Add("session", s.Session)
	resp, err := http.PostForm(commandUrl("key/revoke"), form)
	if err != nil {
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	resp.Body.Close()

	var kr keyResponse
	err = json.Unmarshal(body, &kr)
	if err != nil {
		return
	} else if !kr.Status.Success() {
		err = kr.Status
		return
	}

	s.Token = kr.Token
	return
}

type keySigData struct {
	Fingerprint string `json:"fingerprint"`
	Host        string `json:"host"`
	KeyID       string `json:"key_id"`
	UserID      string `json:"uid"`
	Username    string `json:"username"`
}

type sigDataBody struct {
	Key     keySigData `json:"key"`
	Nonce   string     `json:"string"`
	Type    string     `json:"type"`
	Version int        `json:"version"`
}

type signatureData struct {
	Body      sigDataBody `json:"body"`
	Created   int         `json:"ctime"`
	ExpiresIn int         `json:"expires_in"`
	Tag       string      `json:"tag"`
}

func (s *Session) SignaturePostAuthData() (msg []byte, err error) {
	pub := s.User.PublicKeys["primary"]
	if pub == nil {
		err = ErrNoPublicKey
		return
	}

	var sigData = &signatureData{
		Body: sigDataBody{
			Key: keySigData{
				Fingerprint: pub.Fingerprint,
				Host:        "keybase.io",
				KeyID:       pub.KeyID,
				UserID:      s.User.ID,
				Username:    s.User.Basics.Username,
			},
			Type:    "auth",
			Version: 1,
		},
		Created:   int(time.Now().Unix()),
		ExpiresIn: 86400,
		Tag:       "signature",
	}

	msg, err = json.Marshal(sigData)
	return
}

func (s *Session) SignaturePostAuth(sig []byte) (authToken []byte, err error) {
	var form = url.Values{}
	form.Add("session", s.Session)
	form.Add("csrf_token", s.Token)
	form.Add("email_or_username", s.User.Basics.Username)
	form.Add("sig", string(sig))

	resp, err := http.PostForm(commandUrl("sig/post_auth"), form)
	if err != nil {
		return
	} else if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("HTTP failure: %d - %s", resp.StatusCode, resp.Status)
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	resp.Body.Close()

	var bodyData struct {
		Status    *Status `json:"status"`
		AuthToken string  `json:"auth_token"`
		Token     string  `json:"csrf_token"`
	}

	err = json.Unmarshal(body, &bodyData)
	if err != nil {
		return
	} else if !bodyData.Status.Success() {
		err = bodyData.Status
		return
	}

	s.Token = bodyData.Token
	authToken, err = hex.DecodeString(bodyData.AuthToken)
	return
}

// Retrieve the next sequence number for signatures.
func (s *Session) NextSequence() (seqNum int, prev string, err error) {
	var form = url.Values{}
	form.Add("type", "PUBLIC")
	form.Add("session", s.Session)

	var responseBody struct {
		Status *Status `json:"status"`
		Prev   string  `json:"prev"`
		SeqNo  int     `json:"seqno"`
		Token  string  `json:"csrf_token"`
	}

	resp, err := http.Get(commandUrl("sig/next_seqno") + "?" + form.Encode())
	if err != nil {
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	resp.Body.Close()

	err = json.Unmarshal(body, &responseBody)
	if err != nil {
		fmt.Printf("JSON: %s", string(body))
		return
	} else if !responseBody.Status.Success() {
		err = responseBody.Status
		return
	}

	s.Token = responseBody.Token
	seqNum = responseBody.SeqNo
	prev = responseBody.Prev
	return
}

type signatureBody struct {
	Client struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"client"`
	Key     keySigData `json:"key"`
	Service struct {
		Name     string `json:"name"`
		Username string `json:"username"`
	} `json:"service"`
	Type    string `json:"type"`
	Version int    `json:"version"`
}

type signaturePayload struct {
	Body    signatureBody `json:"body"`
	Created int           `json:"created"`
	Expires int           `json:"expire_in"`
	SeqNo   int           `json:"seqno"`
	Prev    string        `json:"prev"`
}

func (s *Session) serviceBody(svcName, svcUser string) (svcBody *signaturePayload, err error) {
	pub := s.User.PublicKeys["primary"]
	if pub == nil {
		err = ErrNoPublicKey
		return
	}

	svcBody = new(signaturePayload)
	svcBody.Body.Client.Name = "Keybase Go client"
	svcBody.Body.Client.Version = "1.0.0"
	svcBody.Body.Key = keySigData{
		Fingerprint: pub.Fingerprint,
		Host:        "keybase.io",
		KeyID:       pub.KeyID,
		UserID:      s.User.ID,
		Username:    s.User.Basics.Username,
	}
	svcBody.Body.Service.Name = svcName
	svcBody.Body.Service.Username = svcUser
	svcBody.Body.Type = "web_service_binding"
	svcBody.Body.Version = 1
	svcBody.Created = int(time.Now().Unix())
	svcBody.Expires = 157680000 // 5 years

	svcBody.SeqNo, svcBody.Prev, err = s.NextSequence()
	if err != nil {
		svcBody = nil
	}
	return
}

func (s *Session) TwitterGetAuth(username string) (authData []byte, err error) {
	svcBody, err := s.serviceBody("twitter", username)
	if err != nil {
		return
	}
	return json.Marshal(svcBody)
}

func (s *Session) GithubGetAuth(username string) (authData []byte, err error) {
	svcBody, err := s.serviceBody("github", username)
	if err != nil {
		return
	}
	return json.Marshal(svcBody)
}

type rawProof struct {
	Status      *Status `json:"status"`
	Text        string  `json:"proof_text"`
	SigID       string  `json:"sig_id"`
	ProofID     string  `json:"proof_id"`
	PayloadHash string  `json:"payload_hash"`
	Token       string  `json:"csrf_token"`
}

type Proof struct {
	Text        string
	SigID       string
	ProofID     string
	PayloadHash string
}

func (s *Session) ServicePostAuth(sig []byte, user, service string) (proof *Proof, err error) {
	var form = url.Values{}
	form.Add("sig", string(sig))
	form.Add("remote_username", user)
	form.Add("type", fmt.Sprintf("web_service_binding.%s", service))
	form.Add("session", s.Session)
	form.Add("csrf_token", s.Token)

	resp, err := http.PostForm(commandUrl("sig/post"), form)
	if err != nil {
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	resp.Body.Close()

	var rProof rawProof
	err = json.Unmarshal(body, &rProof)
	if err != nil {
		return
	} else if !rProof.Status.Success() {
		err = rProof.Status
		return
	}

	proof = &Proof{
		Text:        rProof.Text,
		SigID:       rProof.SigID,
		ProofID:     rProof.ProofID,
		PayloadHash: rProof.PayloadHash,
	}
	s.Token = rProof.Token
	return
}
