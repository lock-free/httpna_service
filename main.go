package main

import (
	"github.com/lock-free/httpna_service/httpna"
	"github.com/lock-free/httpna_service/oauth"
	"github.com/lock-free/obrero"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"log"
	"os"
	"strconv"
)

// http na for cluster

// user -> http na -> translate to pcp -> na

// http na is also a worker, which exports some worker functions to the outside
const CONFIG_FILE_PATH = "/data/httpna_conf.json"

// curl -d '["proxy", "httpna", ["'", "getServiceType"], 120]' -H "Content-Type: application/json" -X POST http://localhost:8080/api/pcp"
func main() {
	// read conf
	var httpNAConf httpna.HTTPNAConf
	err := obrero.ReadJson(CONFIG_FILE_PATH, &httpNAConf)

	log.Println("read config:")
	log.Println(httpNAConf)

	if err != nil {
		panic(err)
	}

	portText := obrero.MustEnvOption("PORT")
	port, err := strconv.Atoi(portText)
	if err != nil {
		panic(err)
	}

	// load other mids
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
		err := obrero.ReadJson(GOOGLE_OAUTH_CONFIG_FILE_PATH, &googleOAuthConfig)
		if err != nil {
			return err
		}

		log.Println("read google oauth config:")
		log.Println(googleOAuthConfig)

		googleOAuthConfig.Endpoint = google.Endpoint
		var googleOAuthMid = oauth.GetGoogleOAuthMid(googleOAuthConfig, "/oauth/google/login", "/oauth/google/callback")
		oauth.SetUpOAuthRoute(googleOAuthMid, httpNAConf.SESSION_SECRECT_KEY, httpNAConf.SESSION_COOKIE_KEY, httpNAConf.SESSION_PATH, httpNAConf.SESSION_EXPIRE)
	}

	return nil
}

func Exists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}
