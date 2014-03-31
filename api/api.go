package api

func commandUrl(cmd string) string {
	return "https://keybase.io/_/api/1.0/" + cmd + ".json"
}

// Status contains the API call status results from keybase.io.
type Status struct {
	Code int    `json:"code"`
	Name string `json:"name"`
}

// Session contains a keybase session, with user information.
type Session struct {
	Status  Status `json:"status"`
	GuestID string `json:"guest_id"`
	Session string `json:"session"`
	UID     string `json:"uid"`
	User    User   `json:"me"`
	Token   string `json:"csrf_token"`
}
