package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

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
	Code int    `json:"code"`
	Name string `json:"name"`
}

func (st *Status) Error() string {
	return fmt.Sprintf("%d: %s", st.Code, st.Name)
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

	u = userResponse.User
	return
}
