package session

import (
	"net/http"
	"time"
)

// set cookie with key value
// @param sessionKey  []byte   	secrect key
// @param key 			  string 		key of cookie field
// @param value 		  string 		real value of cookie field
// @param path 			  string 		path of cookie field
// @param expire 		  Duration 	minute
func SetSession(w http.ResponseWriter,
	sessionKey []byte,
	key string,
	value string,
	path string,
	expire time.Duration) error {
	if value == "" {
		return nil
	}

	v, err := Encrypt(sessionKey, value) // encrypt value with session key
	if err != nil {
		return err
	}

	expiration := time.Now().Add(expire * time.Minute)

	http.SetCookie(w, &http.Cookie{
		Name:    key,
		Value:   v,
		Path:    path, // example "/"
		Expires: expiration,
	})

	return nil
}

// get session from cookie
// @param sessionKey      []byte   	secrect key
// @param key 			  string 	key of cookie field
func GetSession(r *http.Request,
	sessionKey []byte,
	key string) (string, error) {
	cookie, err := r.Cookie(key)
	if err != nil {
		return "", err
	}
	sourceText, err := Decrypt(sessionKey, cookie.Value)
	if err != nil {
		return "", err
	}
	return sourceText, nil
}

// remove session from cookie
func RemoveSession(w http.ResponseWriter, key string, path string) {
	http.SetCookie(w, &http.Cookie{
		Name:   key,
		Value:  "placed",
		Path:   path,
		MaxAge: -1,
	})
}
