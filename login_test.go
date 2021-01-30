package tglogin

import (
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	id    = 654321
	token = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
	ts    = 1611858140
	hash  = "5185e563403c18f33ce7161de176353852dd1adf41a2e4e3ba185d0822f8f326"
)

var (
	firstName = "first"
	lastName  = "last"
	username  = "usern"
	photoURL  = "https://t.me/i/userpic/320/usern.jpg"
)

func makeUser() User {
	return User{
		ID:        id,
		FirstName: &firstName,
		LastName:  &lastName,
		Username:  &username,
		PhotoURL:  &photoURL,
	}
}

func hasNotSet(u User) bool {
	return u.ID == 0 || u.FirstName == nil || u.LastName == nil ||
		u.Username == nil || u.PhotoURL == nil || u.AuthDate == 0 ||
		u.Hash == ""
}

func TestFromValues(t *testing.T) {
	v := make(url.Values, 7)
	v[keyID] = []string{strconv.Itoa(id)}
	v[keyFirstName] = []string{firstName}
	v[keyLastName] = []string{lastName}
	v[keyUsername] = []string{username}
	v[keyPhotoURL] = []string{photoURL}
	v[keyAuthDate] = []string{strconv.FormatInt(ts, 10)}
	v[keyHash] = []string{hash}
	if hasNotSet(FromValues(v)) {
		t.FailNow()
	}
}

func TestFromReader(t *testing.T) {
	data := `
		{
			"id": 654321,
			"first_name": "first",
			"last_name": "last",
			"username": "usern",
			"photo_url": "https://t.me/i/userpic/320/usern.jpg",
			"auth_date": 1611858140,
			"hash": "5185e563403c18f33ce7161de176353852dd1adf41a2e4e3ba185d0822f8f326"
		}
	`
	if hasNotSet(FromReader(strings.NewReader(data))) {
		t.FailNow()
	}
}

func TestCheckSuccess(t *testing.T) {
	u := makeUser()
	u.AuthDate = ts
	u.Hash = hash
	if err := u.Check(token); err != nil {
		t.Fatal(err)
	}
}

func TestCheckFailureInvalidHash(t *testing.T) {
	u := makeUser()
	u.AuthDate = ts
	u.Hash = hash[:len(hash)/2]
	if err := u.Check(token); err != ErrInvalidHash {
		t.Fatal(err)
	}
}

func TestCheckFailureIsOutdated(t *testing.T) {
	u := makeUser()
	u.AuthDate = time.Now().Add(-OutdatedLimit - time.Second).Unix()
	u.Hash = hex.EncodeToString(u.calc(token))
	if err := u.DateCheck(token); err != ErrIsOutdated {
		t.Fatal(err)
	}
}
