package httpna

import (
	"errors"
	"fmt"
	"github.com/lock-free/gopcp"
	"github.com/lock-free/gopcp_stream"
	"github.com/lock-free/httpna_service/mid"
	"github.com/lock-free/httpna_service/session"
	"github.com/lock-free/obrero"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"
)

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

func ParseProxyCallExp(args []interface{}) (serviceType string, funName string, params []interface{}, timeout time.Duration, err error) {
	var ok = true
	var timeoutf float64

	if len(args) < 3 {
		ok = false
	}

	if ok {
		serviceType, ok = args[0].(string)
	}

	if ok {
		params, ok = args[1].([]interface{})
		if len(params) <= 0 {
			ok = false
		}
	}

	if ok {
		timeoutf, ok = args[2].(float64)
		if ok {
			timeout = time.Duration(timeoutf) * time.Second
		}
	}

	if ok {
		funName, ok = params[0].(string)
	}

	if !ok {
		err = getProxySignError(args)
	} else {
		params = params[1:]
	}

	return
}

// (download, serviceType, [funName, params...], downloadConfig, timeout)
func ParseDownloadCallExp(args []interface{}) (serviceType string, funName string, params []interface{}, downloadConfig map[string]interface{}, timeout time.Duration, err error) {
	var ok = true
	var timeoutf float64

	if len(args) < 3 {
		ok = false
	}

	if ok {
		serviceType, ok = args[0].(string)
	}

	if ok {
		params, ok = args[1].([]interface{})
		if len(params) <= 0 {
			ok = false
		}
	}

	if ok {
		downloadConfig, ok = args[2].(map[string]interface{})
	}

	if ok {
		timeoutf, ok = args[3].(float64)
		if ok {
			timeout = time.Duration(timeoutf) * time.Second
		}
	}

	if ok {
		funName, ok = params[0].(string)
	}

	if !ok {
		err = getProxySignError(args)
	} else {
		params = params[1:]
	}

	return
}

func getUserFromAuthWp(sessionTxt string, naPools obrero.NAPools, authWpName string, authMethod string, timeout time.Duration) (interface{}, error) {
	pcpClient := gopcp.PcpClient{}
	return naPools.CallProxy(authWpName, pcpClient.Call(authMethod, sessionTxt), timeout)
}

func getProxySignError(args []interface{}) error {
	return fmt.Errorf(`"proxy" method signature "(serviceType String, list []Any, timeout Int)" eg: ("user-service", ["getUser", "01234"], 120), args are %v`, args)
}

func getProxyStreamSignError(args []interface{}) error {
	return fmt.Errorf(`"download" method signature "(serviceType String, list []Any, config Map[string]Any, timeout Int)" eg: ("download-service", ["getRecords", 1000], {"contentType": "text/csv(UTF-8)", "filename": "test.csv"}, 120), args are %v`, args)
}

func LogMid(logPrefix string, fn gopcp.GeneralFun) gopcp.GeneralFun {
	return func(args []interface{}, attachment interface{}, pcpServer *gopcp.PcpServer) (ret interface{}, err error) {
		t1 := time.Now().Unix()

		log.Printf("[access-%s] args=%v\n", logPrefix, args)
		ret, err = fn(args, attachment, pcpServer)

		t2 := time.Now().Unix()
		log.Printf("[complete-%s] args=%v, time=%d\n", logPrefix, args, t2-t1)
		return
	}
}

func route(httpNAConf HTTPNAConf) {
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
		// 1. check it's public proxy or private proxy
		// 2. for private proxy, need to call auth service
		"proxy": gopcp.ToSandboxFun(
			LogMid("proxy", mid.FlushPcpFun(func(args []interface{}, attachment interface{}, pcpServer *gopcp.PcpServer) (interface{}, error) {
				httpAttachment := attachment.(mid.HttpAttachment)

				serviceType, funName, params, timeout, err := ParseProxyCallExp(args)
				if err != nil {
					return nil, err
				}

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
					user, err := getUserFromAuthWp(sessionTxt, naPools, httpNAConf.AUTH_WP_NAME, httpNAConf.AUTH_METHOD, timeout)
					if err != nil {
						return nil, &mid.HttpError{
							Errno:  403, // need login
							ErrMsg: err.Error(),
						}
					}

					// 3. add user as first parameter to query private services
					return naPools.CallProxy(serviceType, pcpClient.Call(funName, append([]interface{}{user}, params...)...), timeout)
				} else if _, ok = httpNAConf.PUBLIC_WPS[serviceType]; ok {
					return naPools.CallProxy(serviceType, pcpClient.Call(funName, params...), timeout)
				} else {
					return nil, errors.New("Try to access unexported worker")
				}
			})),
		),

		// download stream data from service
		// (download, serviceType, [funName, params...], downloadConfig, timeout)
		"download": gopcp.ToSandboxFun(
			LogMid("download", func(args []interface{}, attachment interface{}, pcpServer *gopcp.PcpServer) (interface{}, error) {
				httpAttachment := attachment.(mid.HttpAttachment)
				serviceType, funName, params, downloadConfig, timeout, err := ParseDownloadCallExp(args)
				if err != nil {
					httpAttachment.W.Write(mid.ResponseToBytes(mid.ErrorToResponse(err)))
					return nil, nil
				}

				// for private services, need to check user information
				if _, ok := httpNAConf.PRIVATE_WPS[serviceType]; ok {
					// 1. parse http cookie session information
					sessionTxt, err := session.GetSession(httpAttachment.R, []byte(httpNAConf.SESSION_SECRECT_KEY), httpNAConf.SESSION_COOKIE_KEY)

					if err != nil {
						httpAttachment.W.Write(mid.ResponseToBytes(mid.ErrorToResponse(&mid.HttpError{
							Errno:  403, // need login
							ErrMsg: err.Error(),
						})))
						return nil, nil
					}

					// 2. validate session by AUTH application
					user, err := getUserFromAuthWp(sessionTxt, naPools, httpNAConf.AUTH_WP_NAME, httpNAConf.AUTH_METHOD, timeout)
					if err != nil {
						httpAttachment.W.Write(mid.ResponseToBytes(mid.ErrorToResponse(&mid.HttpError{
							Errno:  403, // need login
							ErrMsg: err.Error(),
						})))
						return nil, nil
					}

					// 3. add user as first parameter to query private services
					params = append([]interface{}{user}, params...)
				} else if _, ok = httpNAConf.PUBLIC_WPS[serviceType]; ok {
					//
				} else {
					httpAttachment.W.Write(mid.ResponseToBytes(mid.ErrorToResponse(errors.New("Try to access unexported worker"))))
					return nil, nil
				}

				var wg sync.WaitGroup

				flusher, ok := httpAttachment.W.(http.Flusher)
				if !ok {
					panic("expected http.ResponseWriter to be an http.Flusher")
				}

				// set headers
				httpAttachment.W.Header().Set("X-Content-Type-Options", "nosniff")
				// set filename
				if filenameI, ok := downloadConfig["filename"]; ok {
					if filename, ok := filenameI.(string); ok {
						httpAttachment.W.Header().Set("Content-Disposition", "attachment; "+filename)
					}
				}
				// set content type
				if contentTypeI, ok := downloadConfig["contentType"]; ok {
					if contentType, ok := contentTypeI.(string); ok {
						httpAttachment.W.Header().Set("Content-Disposition", contentType)
					}
				}

				// TODO timeout?
				_, err = naPools.CallProxyStream(serviceType, pcpClient.Call(funName, params...), func(t int, d interface{}) {
					// write response of stream back to client
					switch t {
					case gopcp_stream.STREAM_DATA:
						// d should be a list of texts which means a bundle
						if ds, ok := d.([]interface{}); ok {
							for _, item := range ds {
								fmt.Fprintf(httpAttachment.W, "%s", item)
							}
						} else {
							fmt.Fprintf(httpAttachment.W, "%v", d)
						}

						flusher.Flush()
					case gopcp_stream.STREAM_END:
						wg.Done()
					default:
						if errMsg, ok := d.(string); !ok {
							fmt.Fprintf(httpAttachment.W, "errored at stream, and responsed error message is not string. d=%v", d)
						} else {
							fmt.Fprintf(httpAttachment.W, errMsg)
						}
						flusher.Flush()
						wg.Done()
					}
				}, timeout)

				if err != nil {
					httpAttachment.W.Write(mid.ResponseToBytes(mid.ErrorToResponse(err)))
				} else {
					wg.Add(1)
					// wait for end of stream
					wg.Wait()
				}

				return nil, nil
			}),
		),
	}))

	// http route
	http.HandleFunc("/api/pcp", func(w http.ResponseWriter, r *http.Request) {
		if _, err := pcpMid(w, r, mid.HttpAttachment{R: r, W: w}); err != nil {
			log.Printf("unexpected error at http pcp middleware, %v", err)
		}
	})

	// logout
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		session.RemoveSession(w, httpNAConf.SESSION_COOKIE_KEY, httpNAConf.SESSION_PATH)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	})
}

func StartHttpNAService(httpNAConf HTTPNAConf, port int) {
	route(httpNAConf)
	log.Println("try to start server at " + strconv.Itoa(port))
	log.Fatal(http.ListenAndServe(":"+strconv.Itoa(port), nil))
}
