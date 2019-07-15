package oauth

import (
	"encoding/json"
	"github.com/lock-free/httpna_service/session"
	"net/http"
	"time"
)

type OAuther interface {
	ConstructOAuthUrl(string) string
	GetUserInfo(string, *http.Request) (interface{}, error)
	GetLoginEndPoint() string
	GetCallbackEndPoint() string
}

type SessionUser struct {
	Source string
	User   interface{}
}

func SetUpOAuthRoute(oauther OAuther, sessionSecrectKey string, sessionCookieKey string, sessionPath string, sessionExpire int) {
	http.HandleFunc(oauther.GetLoginEndPoint(), func(w http.ResponseWriter, r *http.Request) {
		// get callback host
		host := GetRedirectHost(r)
		url := oauther.ConstructOAuthUrl(host)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	})

	http.HandleFunc(oauther.GetCallbackEndPoint(), func(w http.ResponseWriter, r *http.Request) {
		host := GetRedirectHost(r)
		user, err := oauther.GetUserInfo(host, r)

		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}

		sessionUser := SessionUser{"google", user}
		value, err := json.Marshal(sessionUser)
		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}

		err = session.SetSession(w,
			[]byte(sessionSecrectKey),
			sessionCookieKey,
			string(value),
			sessionPath,
			time.Duration(sessionExpire)*time.Second)

		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}

		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	})
}

// pass redirect host from front-end
// ...&host=${host}
// host eg: https://a.com
func GetRedirectHost(r *http.Request) string {
	host := r.URL.Scheme + "://" + r.URL.Host

	if hosts, ok := r.URL.Query()["host"]; ok {
		host = hosts[0]
	}
	return host
}
