package main

import (
	"encoding/json"
	"github.com/lock-free/httpna_service/httpna"
	"github.com/lock-free/httpna_service/oauth"
	"github.com/lock-free/httpna_service/session"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

// http na for cluster

// user -> http na -> translate to pcp -> na

// http na is also a worker, which exports some worker functions to the outside
const CONFIG_FILE_PATH = "/data/httpna_conf.json"

// curl -d '["proxy", "httpna", ["'", "getServiceType"], 120]' -H "Content-Type: application/json" -X POST http://localhost:8080/api/pcp"
func main() {
	// read conf
	var httpNAConf httpna.HTTPNAConf
	err := ReadJson(CONFIG_FILE_PATH, &httpNAConf)

	log.Println("read config:")
	log.Println(httpNAConf)

	if err != nil {
		panic(err)
	}

	portText := MustEnvOption("PORT")
	port, err := strconv.Atoi(portText)
	if err != nil {
		panic(err)
	}

	err = GoogleOAuthMid(httpNAConf)
	if err != nil {
		panic(err)
	}

	httpna.StartHttpNAService(httpNAConf, port)
}

const GOOGLE_OAUTH_CONFIG_FILE_PATH = "/data/google_oauth.json"

// google login middleware
func GoogleOAuthMid(httpNAConf httpna.HTTPNAConf) error {
	if Exists(GOOGLE_OAUTH_CONFIG_FILE_PATH) {
		// read conf
		var googleOAuthConfig oauth2.Config
		err := ReadJson(GOOGLE_OAUTH_CONFIG_FILE_PATH, &googleOAuthConfig)

		log.Println("read google oauth config:")
		log.Println(googleOAuthConfig)
		googleOAuthConfig.Endpoint = google.Endpoint

		if err != nil {
			return err
		}

		http.HandleFunc("/oauth/google/login", func(w http.ResponseWriter, r *http.Request) {
			host := r.URL.Scheme + "://" + r.URL.Host

			if hosts, ok := r.URL.Query()["host"]; ok {
				host = hosts[0]
			}

			// copy and change redirect
			var goc = oauth2.Config{
				ClientID:     googleOAuthConfig.ClientID,
				ClientSecret: googleOAuthConfig.ClientSecret,
				Endpoint:     googleOAuthConfig.Endpoint,
				RedirectURL:  host + "/oauth/google/login?host=" + host,
				Scopes:       googleOAuthConfig.Scopes,
			}

			// redirect
			url := goc.AuthCodeURL("state")
			http.Redirect(w, r, url, http.StatusTemporaryRedirect)
		})

		http.HandleFunc("/oauth/google/callback", func(w http.ResponseWriter, r *http.Request) {
			host := r.URL.Scheme + "://" + r.URL.Host

			if hosts, ok := r.URL.Query()["host"]; ok {
				host = hosts[0]
			}

			// copy and change redirect
			var goc = oauth2.Config{
				ClientID:     googleOAuthConfig.ClientID,
				ClientSecret: googleOAuthConfig.ClientSecret,
				Endpoint:     googleOAuthConfig.Endpoint,
				RedirectURL:  host + "/oauth/google/login?host=" + host,
				Scopes:       googleOAuthConfig.Scopes,
			}
			googleUser, err := oauth.GetUserInfoFromGoogle(&goc, r)
			if err != nil {
				w.Write([]byte(err.Error()))
				return
			}

			sessionUser := SessionUser{"google", googleUser}
			value, err := json.Marshal(sessionUser)
			if err != nil {
				w.Write([]byte(err.Error()))
				return
			}

			err = session.SetSession(w,
				[]byte(httpNAConf.SESSION_SECRECT_KEY),
				httpNAConf.SESSION_COOKIE_KEY,
				string(value),
				httpNAConf.SESSION_PATH,
				time.Duration(httpNAConf.SESSION_EXPIRE)*time.Second)

			if err != nil {
				w.Write([]byte(err.Error()))
				return
			}

			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		})
	}

	return nil
}

type SessionUser struct {
	Source string
	User   interface{}
}

func MustEnvOption(envName string) string {
	if v := os.Getenv(envName); v == "" {
		panic("missing env " + envName + " which must exists.")
	} else {
		return v
	}
}

func ReadJson(filePath string, f interface{}) error {
	source, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(source), f)
}

func Exists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}
