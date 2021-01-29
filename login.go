package tglogin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	keyID        = "id"
	keyFirstName = "first_name"
	keyLastName  = "last_name"
	keyUsername  = "username"
	keyPhotoURL  = "photo_url"
	keyAuthDate  = "auth_date"
	keyHash      = "hash"
)

var (
	ErrInvalidHash = errors.New("invalid hash")
	ErrIsOutdated  = errors.New("is outdated")

	OutdatedLimit = 24 * time.Hour
)

type User struct {
	ID        int     `json:"id"`
	FirstName *string `json:"first_name"`
	LastName  *string `json:"last_name"`
	Username  *string `json:"username"`
	PhotoURL  *string `json:"photo_url"`
	AuthDate  int64   `json:"auth_date"`
	Hash      string  `json:"hash"`
}

func (u *User) FromValues(vals url.Values) {
	for k, vs := range vals {
		if len(vs) == 0 {
			continue
		}
		switch k {
		case keyID:
			u.ID, _ = strconv.Atoi(vs[0])
		case keyFirstName:
			firstName := vs[0]
			u.FirstName = &firstName
		case keyLastName:
			lastName := vs[0]
			u.LastName = &lastName
		case keyUsername:
			username := vs[0]
			u.Username = &username
		case keyPhotoURL:
			photoURL := vs[0]
			u.PhotoURL = &photoURL
		case keyAuthDate:
			u.AuthDate, _ = strconv.ParseInt(vs[0], 10, 64)
		case keyHash:
			u.Hash = vs[0]
		}
	}
}

func (u *User) FromReader(r io.Reader) {
	json.NewDecoder(r).Decode(u)
}

func (u User) Check(token string) error {
	mac1, err := hex.DecodeString(u.Hash)
	if err != nil {
		return ErrInvalidHash
	}
	if !hmac.Equal(mac1, u.calc(token)) {
		return ErrInvalidHash
	}
	return nil
}

func (u User) DateCheck(token string) error {
	if err := u.Check(token); err != nil {
		return err
	}
	if u.IsOutdated() {
		return ErrIsOutdated
	}
	return nil
}

func (u User) AuthTime() time.Time {
	return time.Unix(u.AuthDate, 0)
}

func (u User) IsOutdated() bool {
	return u.AuthTime().Add(OutdatedLimit).Before(time.Now())
}

func (u User) calc(token string) []byte {
	key := sha256.Sum256([]byte(token))
	hash := hmac.New(sha256.New, key[:])
	hash.Write([]byte(u.build()))
	return hash.Sum(nil)
}

func (u User) build() string {
	var b strings.Builder
	b.WriteString(keyAuthDate + "=" + strconv.FormatInt(u.AuthDate, 10))
	if u.FirstName != nil {
		b.WriteString("\n" + keyFirstName + "=" + *u.FirstName)
	}
	b.WriteString("\n" + keyID + "=" + strconv.Itoa(u.ID))
	if u.LastName != nil {
		b.WriteString("\n" + keyLastName + "=" + *u.LastName)
	}
	if u.PhotoURL != nil {
		b.WriteString("\n" + keyPhotoURL + "=" + *u.PhotoURL)
	}
	if u.Username != nil {
		b.WriteString("\n" + keyUsername + "=" + *u.Username)
	}
	return b.String()
}

func FromValues(vals url.Values) User {
	var user User
	user.FromValues(vals)
	return user
}

func FromReader(r io.Reader) User {
	var user User
	user.FromReader(r)
	return user
}
