package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/idata-shopee/gopcp"
	"github.com/idata-shopee/gopcp_stream"
	"github.com/lock-free/httpna_service/mid"
	"github.com/lock-free/httpna_service/oauth"
	"github.com/lock-free/httpna_service/session"
	"github.com/lock-free/obrero"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

// http na for cluster

// user -> http na -> translate to pcp -> na

// http na is also a worker, which exports some worker functions to the outside

type HttpAttachment struct {
	W http.ResponseWriter
	R *http.Request
}

type HTTPNAConf struct {
	PRIVATE_WPS         map[string]bool
	PUBLIC_WPS          map[string]bool
	AUTH_WP_NAME        string
	AUTH_METHOD         string
	SESSION_COOKIE_KEY  string
	SESSION_SECRECT_KEY string
	SESSION_PATH        string
	SESSION_EXPIRE      int
}

func getUserFromAuthWp(sessionTxt string, naPools obrero.NAPools, authWpName string, authMethod string, timeout time.Duration) (interface{}, error) {
	pcpClient := gopcp.PcpClient{}
	return naPools.CallProxy(authWpName, pcpClient.Call(authMethod, sessionTxt), timeout)
}

func getProxySignError(args []interface{}) error {
	return fmt.Errorf(`httpna: "proxy" method signature "(serviceType String, params, timeout)", args are %v`, args)
}

const CONFIG_FILE_PATH = "/data/httpna_conf.json"

// curl -d '["proxy", "httpna", "[\"getServiceType\"]", 120]' -H "Content-Type: application/json" -X POST http://localhost:8080/api/pcp"
func main() {
	// read conf
	var httpNAConf HTTPNAConf
	err := ReadJson(CONFIG_FILE_PATH, &httpNAConf)

	log.Println("read config:")
	log.Println(httpNAConf)

	if err != nil {
		panic(err)
	}

	pcpClient := gopcp.PcpClient{}

	naPools := obrero.StartWorker(func(*gopcp_stream.StreamServer) *gopcp.Sandbox {
		return gopcp.GetSandbox(map[string]*gopcp.BoxFunc{
			"getServiceType": gopcp.ToSandboxFun(func(args []interface{}, attachment interface{}, pcpServer *gopcp.PcpServer) (interface{}, error) {
				return "httpna", nil
			}),
		})
	}, obrero.WorkerStartConf{
		PoolSize:            2,
		Duration:            20 * time.Second,
		RetryDuration:       20 * time.Second,
		NAGetClientMaxRetry: 3,
	})

	// middleware for proxy http request to wp
	pcpMid := mid.GetPcpMid(gopcp.GetSandbox(map[string]*gopcp.BoxFunc{
		// [proxy, serviceType, exp, timeout]
		"proxy": gopcp.ToLazySandboxFun(func(args []interface{}, attachment interface{}, pcpServer *gopcp.PcpServer) (interface{}, error) {
			httpAttachment := attachment.(HttpAttachment)

			// 1. check it's public proxy or private proxy
			// 2. for private proxy, need to call auth service
			if len(args) < 3 {
				return nil, getProxySignError(args)
			}
			var (
				serviceType string
				timeout     float64
				ok          bool
			)

			serviceType, ok = args[0].(string)
			if !ok {
				return nil, getProxySignError(args)
			}

			timeout, ok = args[2].(float64)
			if !ok {
				return nil, getProxySignError(args)
			}

			params, ok := args[1].([]interface{})
			if !ok {
				return nil, getProxySignError(args)
			}

			if len(params) <= 0 {
				return nil, getProxySignError(args)
			}

			funName, ok := params[0].(string)

			if !ok {
				return nil, getProxySignError(args)
			}

			timeoutDuration := time.Duration(int(timeout)) * time.Second
			// for private services, need to check user information
			if _, ok := httpNAConf.PRIVATE_WPS[serviceType]; ok {
				// 1. parse http cookie session information
				sessionTxt, err := session.GetSession(httpAttachment.R, []byte(httpNAConf.SESSION_SECRECT_KEY), httpNAConf.SESSION_COOKIE_KEY)

				if err != nil {
					return nil, &mid.HttpError{
						Errno:  403, // need login
						ErrMsg: err.Error(),
					}
				}

				// 2. validate session by AUTH application
				user, err := getUserFromAuthWp(sessionTxt, naPools, httpNAConf.AUTH_WP_NAME, httpNAConf.AUTH_METHOD, timeoutDuration)
				if err != nil {
					return nil, err
				}

				// 3. add user as first parameter to query private services
				return naPools.CallProxy(serviceType, pcpClient.Call(funName, append([]interface{}{user}, params[1:]...)), timeoutDuration)
			} else if _, ok = httpNAConf.PUBLIC_WPS[serviceType]; ok {
				return naPools.CallProxy(serviceType, pcpClient.Call(funName, params[1:]...), timeoutDuration)
			} else {
				return nil, errors.New("Try to access unexported worker")
			}
		}),
	}))

	// http route
	http.HandleFunc("/api/pcp", func(w http.ResponseWriter, r *http.Request) {
		if _, err := pcpMid(w, r, HttpAttachment{R: r, W: w}); err != nil {
			log.Printf("unexpected error at http pcp middleware, %v", err)
		}
	})

	err = GoogleOAuthMid(httpNAConf)
	if err != nil {
		panic(err)
	}

	// TODO read port from env
	port := MustEnvOption("PORT")
	log.Println("try to start server at " + port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

const GOOGLE_OAUTH_CONFIG_FILE_PATH = "/data/google_oauth.json"

// google login middleware
func GoogleOAuthMid(httpNAConf HTTPNAConf) error {
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
			oauth.RedirectToGoogleOAuthUrl(&googleOAuthConfig, w, r)
		})

		http.HandleFunc("/oauth/google/callback", func(w http.ResponseWriter, r *http.Request) {
			googleUser, err := oauth.GetUserInfoFromGoogle(&googleOAuthConfig, r)
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
