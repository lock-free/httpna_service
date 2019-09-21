package httpna

import (
	"errors"
	"fmt"
	"github.com/lock-free/goklog"
	"github.com/lock-free/gopcp"
	"github.com/lock-free/gopcp_rpc"
	"github.com/lock-free/gopcp_stream"
	"github.com/lock-free/httpna_service/mid"
	"github.com/lock-free/httpna_service/session"
	"github.com/lock-free/obrero"
	"github.com/lock-free/obrero/mids"
	"github.com/lock-free/obrero/napool"
	"net/http"
	"strconv"
	"time"
)

var klog = goklog.GetInstance()
var pcpClient = gopcp.PcpClient{}

type HTTPNAConf struct {
	PORT                int
	PRIVATE_WPS         map[string]bool
	PUBLIC_WPS          map[string]bool
	AUTH_WP_NAME        string
	AUTH_METHOD         string
	SESSION_COOKIE_KEY  string
	SESSION_SECRECT_KEY string
	SESSION_PATH        string
	SESSION_EXPIRE      int
	OAuth               []OAuthConf
}

type OAuthConf struct {
	LoginEndPoint    string
	CallbackEndPoint string
	ServiceType      string
}

func getUserFromAuthWp(sessionTxt string, naPools napool.NAPools, authWpName string, authMethod string, timeout time.Duration) (interface{}, error) {
	pcpClient := gopcp.PcpClient{}
	return naPools.CallProxy(authWpName, pcpClient.Call(authMethod, sessionTxt), timeout)
}

func Route(httpNAConf HTTPNAConf) napool.NAPools {
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

	var proxyMid = mids.GetProxyMid(func(serviceType string) (*gopcp_rpc.PCPConnectionHandler, error) {
		return naPools.GetRandomItem()
	}, func(exp interface{}, serviceType string, timeout int, attachment interface{}, pcpServer *gopcp.PcpServer) (string, error) {
		httpAttachment := attachment.(mid.HttpAttachment)
		var timeoutD = time.Duration(timeout) * time.Second

		// to array
		jsonObj := gopcp.ParseAstToJsonObject(exp)
		arr, ok := jsonObj.([]interface{})
		if !ok || len(arr) == 0 {
			return "", fmt.Errorf("Expect none-empty array, but got %v", jsonObj)
		}

		// for private services, need to check user information
		if _, ok := httpNAConf.PRIVATE_WPS[serviceType]; ok {
			// 1. parse http cookie session information
			sessionTxt, err := session.GetSession(httpAttachment.R, []byte(httpNAConf.SESSION_SECRECT_KEY), httpNAConf.SESSION_COOKIE_KEY)

			if err != nil {
				return "", &mid.HttpError{
					Errno:  403, // need login
					ErrMsg: err.Error(),
				}
			}

			// 2. validate session by AUTH application
			user, err := getUserFromAuthWp(sessionTxt, naPools, httpNAConf.AUTH_WP_NAME, httpNAConf.AUTH_METHOD, timeoutD)
			if err != nil {
				return "", &mid.HttpError{
					Errno:  403, // need login
					ErrMsg: err.Error(),
				}
			}

			// 3. add user as first parameter to query private services
			return pcpClient.ToJSON(gopcp.CallResult{append([]interface{}{arr[0], user}, arr[1:]...)})
		}

		if _, ok := httpNAConf.PUBLIC_WPS[serviceType]; ok {
			return pcpClient.ToJSON(gopcp.CallResult{append([]interface{}{arr[0]}, arr[1:]...)})
		}

		return "", errors.New("Try to access unexported worker")
	})

	// middleware for proxy http request to wp
	pcpMid := mid.GetPcpMid(gopcp.GetSandbox(map[string]*gopcp.BoxFunc{
		// [proxy, serviceType, exp, timeout]
		// 1. check it's public proxy or private proxy
		// 2. for private proxy, need to call auth service
		"proxy": gopcp.ToLazySandboxFun(
			mids.LogMid("proxy", mid.FlushPcpFun(proxyMid.Proxy)),
		),
	}))

	// http route
	http.HandleFunc("/api/pcp", func(w http.ResponseWriter, r *http.Request) {
		if _, err := pcpMid(w, r, mid.HttpAttachment{R: r, W: w}); err != nil {
			klog.LogError("pcp-mid", err)
		}
	})

	// logout
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		session.RemoveSession(w, httpNAConf.SESSION_COOKIE_KEY, httpNAConf.SESSION_PATH)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	})

	return naPools
}

func StartHttpServer(port int) {
	klog.LogNormal("start-service", "try to start tcp server at "+strconv.Itoa(port))
	err := http.ListenAndServe(":"+strconv.Itoa(port), nil)
	if err != nil {
		panic(err)
	}
}
