package httpna

import (
	"fmt"
	"github.com/lock-free/goklog"
	"github.com/lock-free/gopcp"
	"github.com/lock-free/gopcp_rpc"
	"github.com/lock-free/gopcp_stream"
	"github.com/lock-free/obrero"
	"github.com/lock-free/obrero/mids"
	"github.com/lock-free/obrero/mids/httpmids"
	"github.com/lock-free/obrero/napool"
	"net/http"
	"strconv"
	"time"
)

var klog = goklog.GetInstance()
var pcpClient = gopcp.PcpClient{}

type HTTPNAConf struct {
	PORT               int
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
		httpAttachment := attachment.(httpmids.HttpAttachment)
		var timeoutD = time.Duration(timeout) * time.Second

		// to array
		jsonObj := gopcp.ParseAstToJsonObject(exp)
		arr, ok := jsonObj.([]interface{})
		if !ok || len(arr) == 0 {
			return "", fmt.Errorf("Expect none-empty array, but got %v", jsonObj)
		}

		// for private services, need to check user information
		if _, ok := httpNAConf.PRIVATE_WPS[serviceType]; ok {
			cookie, err := httpAttachment.R.Cookie(httpNAConf.SESSION_COOKIE_KEY)
			if err != nil {
				return "", &httpmids.HttpError{
					Errno:  403, // need login
					ErrMsg: err.Error(),
				}
			}

			// get uid
			uid, err := naPools.CallProxy("session_obrero", pcpClient.Call("getUidFromSessionText", cookie.Value, timeout), timeoutD)
			if err != nil {
				return "", &httpmids.HttpError{
					Errno:  403, // need login
					ErrMsg: err.Error(),
				}
			}

			// add user as first parameter to query private services
			return pcpClient.ToJSON(pcpClient.Call("proxy", serviceType, gopcp.CallResult{append([]interface{}{arr[0], uid}, arr[1:]...)}, timeout))
		}

		if _, ok := httpNAConf.PUBLIC_WPS[serviceType]; ok {
			return pcpClient.ToJSON(pcpClient.Call("proxy", serviceType, gopcp.CallResult{arr}, timeout))
		}

		return "", fmt.Errorf("Try to access unexported worker: %s", serviceType)
	})

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
			Name:   httpNAConf.SESSION_COOKIE_KEY,
			Value:  "placed",
			Path:   httpNAConf.SESSION_PATH,
			MaxAge: -1,
		})

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
