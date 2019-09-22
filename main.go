package main

import (
	"encoding/json"
	"github.com/lock-free/gopcp"
	"github.com/lock-free/httpna_service/httpna"
	"github.com/lock-free/obrero/utils"
	"log"
	"net/http"
	"time"
)

// http na for cluster

// http na is also a worker, which exports some worker functions to the outside
const CONFIG_FILE_PATH = "/data/httpna_conf.json"

func main() {
	// read conf
	var httpNAConf httpna.HTTPNAConf
	err := utils.ReadJson(CONFIG_FILE_PATH, &httpNAConf)

	log.Println("read config:")
	log.Println(httpNAConf)

	if err != nil {
		panic(err)
	}

	naPools := httpna.Route(httpNAConf)
	pcpClient := gopcp.PcpClient{}

	// dynamic oauth middlewares
	for _, oauthConf := range httpNAConf.OAuth {
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

			sessionUser := SessionUser{"google", user}
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
				Name:    httpNAConf.SESSION_COOKIE_KEY,
				Value:   cypherText,
				Path:    httpNAConf.SESSION_PATH,
				Expires: time.Now().Add(time.Duration(httpNAConf.SESSION_EXPIRE) * time.Second),
			})

			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		})
	}

	// TODO dynamic proxy middlewares

	httpna.StartHttpServer(httpNAConf.PORT)
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
