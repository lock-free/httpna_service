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

type GoogleOAuthMid struct {
	googleOAuthConfig oauth2.Config
	loginEndPoint     string
	callbackEndPoint  string
}

func GetGoogleOAuthMid(googleOAuthConfig oauth2.Config, loginEndPoint string, callbackEndPoint string) *GoogleOAuthMid {
	return &GoogleOAuthMid{
		googleOAuthConfig,
		loginEndPoint,
		callbackEndPoint,
	}
}
func (g GoogleOAuthMid) GetLoginEndPoint() string {
	return g.loginEndPoint
}

func (g GoogleOAuthMid) GetCallbackEndPoint() string {
	return g.callbackEndPoint
}

func (g GoogleOAuthMid) ConstructOAuthUrl(callbackHost string) string {
	// copy and change redirect
	var goc = oauth2.Config{
		ClientID:     g.googleOAuthConfig.ClientID,
		ClientSecret: g.googleOAuthConfig.ClientSecret,
		Endpoint:     g.googleOAuthConfig.Endpoint,
		RedirectURL:  callbackHost + "/oauth/google/callback?host=" + callbackHost,
		Scopes:       g.googleOAuthConfig.Scopes,
	}

	// construct redirect url
	return goc.AuthCodeURL("state")
}

func (g GoogleOAuthMid) GetUserInfo(callbackHost string, r *http.Request) (interface{}, error) {
	// copy and change redirect
	var goc = oauth2.Config{
		ClientID:     g.googleOAuthConfig.ClientID,
		ClientSecret: g.googleOAuthConfig.ClientSecret,
		Endpoint:     g.googleOAuthConfig.Endpoint,
		RedirectURL:  callbackHost + "/oauth/google/callback?host=" + callbackHost,
		Scopes:       g.googleOAuthConfig.Scopes,
	}
	return GetUserInfoFromGoogle(&goc, r)
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
