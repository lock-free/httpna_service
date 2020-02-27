package main

import (
	"encoding/json"
	"errors"
	"fmt"
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
				klog.LogNormal("oauth-end",
					fmt.Sprintf("login end point=%s, serviceType=%s\n", oauthConf.LoginEndPoint, oauthConf.ServiceType))

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
					w.Write([]byte(fmt.Sprintf("unexpected worker error: url is not string, url is %v", url)))
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

				err = SetAuthTokenToClient(naPools, w, appConfig, sessionUser)
				if err != nil {
					w.Write([]byte(err.Error()))
					return
				}

				http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			})
		}(oauthConf)
	}
}

func SetAuthTokenToClient(naPools *napool.NAPools, w http.ResponseWriter, appConfig AppConfig, sessionUser SessionUser) error {
	value, err := json.Marshal(sessionUser)
	if err != nil {
		return err
	}

	cypher, err := naPools.CallProxy("session_obrero", pcpClient.Call("encryptSession", string(value)), 120*time.Second)
	if err != nil {
		return err
	}
	cypherText, ok := cypher.(string)
	if !ok {
		return errors.New("unexpect type error for encryptSession")
	}

	http.SetCookie(w, &http.Cookie{
		Name:    appConfig.SESSION_COOKIE_KEY,
		Value:   cypherText,
		Path:    appConfig.SESSION_PATH,
		Expires: time.Now().Add(time.Duration(appConfig.SESSION_EXPIRE) * time.Second),
	})

	return nil
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
