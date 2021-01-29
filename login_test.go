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
	id    = 123456
	token = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
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

func TestFromValues(t *testing.T) {
	v := make(url.Values, 7)
	v[keyID] = []string{strconv.Itoa(id)}
	v[keyFirstName] = []string{firstName}
	v[keyLastName] = []string{lastName}
	v[keyUsername] = []string{username}
	v[keyPhotoURL] = []string{photoURL}
	v[keyAuthDate] = []string{strconv.FormatInt(time.Now().Unix(), 10)}
	v[keyHash] = []string{"a"}
	u, err := FromValues(v)
	if err != nil || u.ID != id || u.FirstName == nil || u.LastName == nil ||
		u.Username == nil || u.PhotoURL == nil || u.AuthDate == 0 ||
		u.Hash == "" {

		t.Fatal(err)
	}
}

func TestFromReader(t *testing.T) {
	data := `
		{
			"id": 123456,
			"first_name": "first",
			"last_name": "last",
			"username": "usern",
			"photo_url": "https://t.me/i/userpic/320/usern.jpg",
			"auth_date": 1,
			"hash": "a"
		}
	`
	u, err := FromReader(strings.NewReader(data))
	if err != nil || u.ID != id || u.FirstName == nil || u.LastName == nil ||
		u.Username == nil || u.PhotoURL == nil || u.AuthDate == 0 ||
		u.Hash == "" {

		t.Fatal(err)
	}
}

func TestCheckSuccess(t *testing.T) {
	u := makeUser()
	u.AuthDate = time.Now().Unix()
	u.Hash = hex.EncodeToString(u.calc(token))
	if err := u.Check(token); err != nil {
		t.Fatal(err)
	}
}

func TestCheckFailureInvalidHash(t *testing.T) {
	u := makeUser()
	u.AuthDate = time.Now().Unix()
	u.Hash = "a9cf12636fb07b54b4c95673d017a72364472c41a760b6850bcd5405da769f80"
	if err := u.Check(token); err != ErrInvalidHash {
		t.Fatal(err)
	}
}

func TestCheckFailureIsOutdated(t *testing.T) {
	u := makeUser()
	u.AuthDate = time.Now().Add(-OutdatedLimit).Unix()
	u.Hash = hex.EncodeToString(u.calc(token))
	if err := u.DateCheck(token); err != ErrIsOutdated {
		t.Fatal(err)
	}
}
