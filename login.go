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
	ErrNotFilled   = errors.New("not filled")
	ErrInvalidHash = errors.New("invalid hash")
	ErrIsOutdated  = errors.New("is outdated")

	OutdatedLimit = 24 * time.Hour
)

type User struct {
	ID        int64   `json:"id"`
	FirstName *string `json:"first_name"`
	LastName  *string `json:"last_name"`
	Username  *string `json:"username"`
	PhotoURL  *string `json:"photo_url"`
	AuthDate  int64   `json:"auth_date"`
	Hash      string  `json:"hash"`
}

func (u *User) FromValues(vs url.Values) {
	for k, l := range vs {
		if len(l) == 0 {
			continue
		}
		switch k {
		case keyID:
			u.ID, _ = strconv.ParseInt(l[0], 10, 64)
		case keyFirstName:
			v1 := l[0]
			u.FirstName = &v1
		case keyLastName:
			v2 := l[0]
			u.LastName = &v2
		case keyUsername:
			v3 := l[0]
			u.Username = &v3
		case keyPhotoURL:
			v4 := l[0]
			u.PhotoURL = &v4
		case keyAuthDate:
			u.AuthDate, _ = strconv.ParseInt(l[0], 10, 64)
		case keyHash:
			u.Hash = l[0]
		}
	}
}

func (u *User) FromReader(r io.Reader) {
	json.NewDecoder(r).Decode(u)
}

func (u User) Check(token string) error {
	if u.ID == 0 || u.AuthDate == 0 || u.Hash == "" {
		return ErrNotFilled
	}
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
	b.WriteString("\n" + keyID + "=" + strconv.FormatInt(u.ID, 10))
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

func FromValues(vs url.Values) User {
	var user User
	user.FromValues(vs)
	return user
}

func FromReader(r io.Reader) User {
	var user User
	user.FromReader(r)
	return user
}
