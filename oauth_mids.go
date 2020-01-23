package main

import (
	"encoding/json"
	"github.com/lock-free/obrero/napool"
	"log"
	"net/http"
	"time"
)

func OAuthMids(naPools *napool.NAPools, appConfig AppConfig) {
	// dynamic oauth middlewares
	// oauth interactive protocol:
	// (1) construct oauth url used to redirect to login page from front end
	//     (constructOAuthUrl, host, CallbackEndPoint)
	// (2) get user info from callback by oauth
	//     (getUserInfo, host, url, CallbackEndPoint)
	for _, oauthConf := range appConfig.OAuth {
		func(oauthConf OAuthConf) {
			http.HandleFunc(oauthConf.LoginEndPoint, func(w http.ResponseWriter, r *http.Request) {
				// get callback host
				host := GetRedirectHost(r)
				v, err := naPools.CallProxy(oauthConf.ServiceType,
					pcpClient.Call("constructOAuthUrl", host, oauthConf.CallbackEndPoint),
					2*time.Minute)
				if err != nil {
					w.Write([]byte(err.Error()))
					return
				}

				url, ok := v.(string)
				if !ok {
					w.Write([]byte("unexpected worker error: url is not string"))
					return
				}
				log.Printf("login redict url is: %s", url)
				http.Redirect(w, r, url, http.StatusTemporaryRedirect)
			})

			http.HandleFunc(oauthConf.CallbackEndPoint, func(w http.ResponseWriter, r *http.Request) {
				host := GetRedirectHost(r)
				user, err := naPools.CallProxy(oauthConf.ServiceType,
					pcpClient.Call("getUserInfo", host, r.URL.String(), oauthConf.CallbackEndPoint),
					2*time.Minute)

				if err != nil {
					w.Write([]byte(err.Error()))
					return
				}

				sessionUser := SessionUser{oauthConf.LoginType, user}
				value, err := json.Marshal(sessionUser)
				if err != nil {
					w.Write([]byte(err.Error()))
					return
				}

				cypher, err := naPools.CallProxy("session_obrero", pcpClient.Call("encryptSession", string(value)), 120*time.Second)
				if err != nil {
					w.Write([]byte(err.Error()))
					return
				}
				cypherText, ok := cypher.(string)
				if !ok {
					w.Write([]byte("unexpect type error for encryptSession"))
					return
				}

				http.SetCookie(w, &http.Cookie{
					Name:    appConfig.SESSION_COOKIE_KEY,
					Value:   cypherText,
					Path:    appConfig.SESSION_PATH,
					Expires: time.Now().Add(time.Duration(appConfig.SESSION_EXPIRE) * time.Second),
				})

				http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			})
		}(oauthConf)
	}
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

type SessionUser struct {
	Source string
	User   interface{}
}
