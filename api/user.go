package api

// User contains information regarding a user.
type User struct {
	ID          string          `json:"id"`
	Basics      Basics          `json:"basics"`
	Invitations InvitationStats `json:"invitation_stats"`
	Profile     Profile         `json:"profile"`
	Emails      Emails          `json:"emails"`
	PublicKeys  map[string]*Key `json:"public_keys"`
	PrivateKeys map[string]*Key `json:"private_keys"`
}

// Basics contain basic information about the user.
type Basics struct {
	Username     string `json:"username"`
	Created      int    `json:"ctime"`
	Modified     int    `json:"mtime"`
	IDVersion    int    `json:"id_version"`
	TrackVersion int    `json:"track_version"`
	LastIDChange int    `json:"last_id_change"`
	Salt         string `json:"string"`
}

// InvitationStats contains the user's invitation stats.
type InvitationStats struct {
	Available int `json:"available"`
	Used      int `json:"used"`
	Power     int `json:"power"`
	Open      int `json:"open"`
}

// Profile contains the user's profile information.
type Profile struct {
	Modified int    `json:"mtime"`
	FullName string `json:"full_name"`
	Location string `json:"location"`
	Bio      string `json:"bio"`
}

// Users contains an email record.
type Email struct {
	Email    string `json:"email"`
	Verified int    `json:"is_verified"`
}

// Emails contains a list of the user's emails. Right now, only a primary
// email is contained in this structure.
type Emails struct {
	Primary Email `json:"primary"`
}

// A KeyType is used to denote whether a key is public or private.
type KeyType int

// These constants provide friendly names for the key types returned by
// the API.
const (
	PublicKey  KeyType = 1
	PrivateKey KeyType = 2
)

// A Key contains information about a public or private key.
type Key struct {
	KeyID       string  `json:"kid"`
	Fingerprint string  `json:"key_fingerprint"`
	KeyType     KeyType `json:"key_type"`
	Bundle      string  `json:"bundle"`
	Modified    int     `json:"mtime"`
	Created     int     `json:"ctime"`
}
