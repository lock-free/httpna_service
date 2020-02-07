package main

import (
	"fmt"
	"github.com/lock-free/goklog"
	"github.com/lock-free/gopcp"
	"github.com/lock-free/gopcp_rpc"
	"github.com/lock-free/gopcp_stream"
	"github.com/lock-free/obrero/mids"
	"github.com/lock-free/obrero/mids/httpmids"
	"github.com/lock-free/obrero/napool"
	"github.com/lock-free/obrero/stdserv"
	"github.com/lock-free/obrero/utils"
	"net/http"
	"strconv"
	"time"
)

var klog = goklog.GetInstance()
var pcpClient = gopcp.PcpClient{}

// http na is also a worker, which exports some worker functions to the outside
const CONFIG_FILE_PATH = "/data/app.json"

type AppConfig struct {
	PORT               int
	Admins             map[string]interface{}
	PRIVATE_WPS        map[string]bool
	PUBLIC_WPS         map[string]bool
	SESSION_COOKIE_KEY string
	SESSION_PATH       string
	SESSION_EXPIRE     int
	OAuth              []OAuthConf
}

type OAuthConf struct {
	LoginEndPoint    string
	CallbackEndPoint string
	ServiceType      string
	LoginType        string
}

func getUid(naPools *napool.NAPools, appConfig *AppConfig, httpAttachment httpmids.HttpAttachment, timeout int) (string, error) {

	var timeoutD = time.Duration(timeout) * time.Second
	cookie, err := httpAttachment.R.Cookie(appConfig.SESSION_COOKIE_KEY)
	if err != nil {
		return "", &httpmids.HttpError{
			Errno:  403, // need login
			ErrMsg: err.Error(),
		}
	}

	// get uid
	var uid string
	uidInterface, err := naPools.CallProxy("session_obrero", pcpClient.Call("getUidFromSessionText", cookie.Value, timeout), timeoutD)
	if err != nil {
		return "", &httpmids.HttpError{
			Errno:  403, // need login
			ErrMsg: err.Error(),
		}
	}
	err = utils.ParseArg(uidInterface, &uid)
	if err != nil {
		return "", err
	}

	return uid, err
}

func getExpAsArr(exp gopcp.FunNode) ([]interface{}, error) {
	jsonObj := gopcp.ParseAstToJsonObject(exp)
	arr, ok := jsonObj.([]interface{})
	if !ok || len(arr) == 0 {
		return nil, fmt.Errorf("Expect none-empty array, but got %v, exp is %v", jsonObj, exp)
	}
	return arr, nil
}

func Route(naPools *napool.NAPools, appConfig AppConfig) {
	var getWorkerHandler = func(serviceType string, workerId string) (*gopcp_rpc.PCPConnectionHandler, error) {
		return naPools.GetRandomItem()
	}

	var getCommand = func(exp gopcp.FunNode, serviceType string, timeout int, attachment interface{}, pcpServer *gopcp.PcpServer) (string, error) {
		httpAttachment := attachment.(httpmids.HttpAttachment)

		// to array
		arr, err := getExpAsArr(exp)
		if err != nil {
			return "", err
		}

		// for public service
		if _, ok := appConfig.PUBLIC_WPS[serviceType]; ok {
			return pcpClient.ToJSON(pcpClient.Call("proxy", serviceType, gopcp.CallResult{arr}, timeout))
		} else {
			uid, err := getUid(naPools, &appConfig, httpAttachment, timeout)
			if err != nil {
				return "", err
			}

			// for private services, need to check user information
			if _, ok := appConfig.PRIVATE_WPS[serviceType]; ok {
				// add user as first parameter to query private services
				return pcpClient.ToJSON(pcpClient.Call("proxy", serviceType, gopcp.CallResult{append([]interface{}{arr[0], uid}, arr[1:]...)}, timeout))
			}
		}

		return "", fmt.Errorf("Try to access unexported worker: %s", serviceType)
	}

	var getAdminCommand = func(exp gopcp.FunNode, serviceType string, timeout int, attachment interface{}, pcpServer *gopcp.PcpServer) (string, error) {
		httpAttachment := attachment.(httpmids.HttpAttachment)

		// to array
		arr, err := getExpAsArr(exp)
		if err != nil {
			return "", err
		}
		uid, err := getUid(naPools, &appConfig, httpAttachment, timeout)
		if err != nil {
			return "", err
		}

		klog.LogNormal("admin-pcp", uid)
		// TODO admin checking
		return pcpClient.ToJSON(pcpClient.Call("proxy", serviceType, gopcp.CallResult{arr}, timeout))
	}

	var proxyMid = mids.GetProxyMid(getWorkerHandler, getCommand)

	// middleware for proxy http request to wp
	pcpMid := httpmids.GetPcpMid(gopcp.GetSandbox(map[string]*gopcp.BoxFunc{
		// [proxy, serviceType, exp, timeout]
		// 1. check it's public proxy or private proxy
		// 2. for private proxy, need to call auth service
		"proxy": gopcp.ToLazySandboxFun(mids.LogMid("proxy", httpmids.FlushPcpFun(proxyMid.Proxy))),
	}))

	// http route
	http.HandleFunc("/api/pcp", func(w http.ResponseWriter, r *http.Request) {
		if _, err := pcpMid(w, r, httpmids.HttpAttachment{R: r, W: w}); err != nil {
			klog.LogError("pcp-mid", err)
		}
	})

	// logout
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		// remove session from cookie
		http.SetCookie(w, &http.Cookie{
			Name:   appConfig.SESSION_COOKIE_KEY,
			Value:  "placed",
			Path:   appConfig.SESSION_PATH,
			MaxAge: -1,
		})

		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	})
}

func main() {
	// read config
	var appConfig AppConfig

	// connect NAs
	naPools := stdserv.StartStdWorker(&appConfig, nil, func(naPools *napool.NAPools, workerState *stdserv.WorkerState, s *gopcp_stream.StreamServer) map[string]*gopcp.BoxFunc {
		return map[string]*gopcp.BoxFunc{
			"getServiceType": gopcp.ToSandboxFun(func(args []interface{}, attachment interface{}, pcpServer *gopcp.PcpServer) (interface{}, error) {
				return "httpna", nil
			}),
		}
	}, stdserv.StdWorkerConfig{
		ServiceName: "ddki_app",
		Nonblocking: true,
	})

	// mids
	Route(&naPools, appConfig)
	OAuthMids(&naPools, appConfig)

	// start server
	klog.LogNormal("start-service", "try to start tcp server at "+strconv.Itoa(appConfig.PORT))
	err := http.ListenAndServe(":"+strconv.Itoa(appConfig.PORT), nil)
	if err != nil {
		panic(err)
	}
}
