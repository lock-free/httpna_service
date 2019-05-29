package oauth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"golang.org/x/oauth2"
)

type GoogleUser struct {
	ID            string
	Email         string
	VerifiedEmail string
	Name          string
	GivenName     string
	FamilyName    string
	Link          string
	Picture       string
	Locale        string
	HD            string
}

// redirect to goole oauth url
func RedirectToGoogleOAuthUrl(config *oauth2.Config, w http.ResponseWriter, r *http.Request) {
	url := config.AuthCodeURL("state")
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// call this to get user when callback
func GetUserInfoFromGoogle(conf *oauth2.Config, r *http.Request) (GoogleUser, error) {
	var googleUser GoogleUser

	state, code := r.FormValue("state"), r.FormValue("code")

	if state != "state" {
		return googleUser, fmt.Errorf("Invalid OAuth state")
	}

	token, err := conf.Exchange(oauth2.NoContext, code)
	if err != nil {
		return googleUser, fmt.Errorf("code exchange failed: %s", err.Error())
	}

	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		return googleUser, fmt.Errorf("failed getting user info: %s", err.Error())
	}

	defer response.Body.Close()
	content, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return googleUser, fmt.Errorf("failed reading response body: %s", err.Error())
	}
	json.Unmarshal([]byte(content), &googleUser)

	return googleUser, nil
}
