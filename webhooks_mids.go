package main

import (
	"github.com/lock-free/obrero/napool"
	"github.com/lock-free/obrero/utils"
	"io/ioutil"
	"net/http"
	"time"
)

// webHook service function signature:
//    (url string, method string, headers map[string][]string, body string)
//         -> {status int, headers map[string][]string, body string}

// Header: https://godoc.org/net/http#Header

type WebHookResponse struct {
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

func WebHookMids(naPools *napool.NAPools, appConfig AppConfig) {
	for _, webHook := range appConfig.WebHooks {
		func(webHook WebHookConf) {
			http.HandleFunc(webHook.WebHookEndPoint, func(w http.ResponseWriter, r *http.Request) {
				body, err := ioutil.ReadAll(r.Body)
				if err != nil {
					http.Error(w, "can't read body", http.StatusBadRequest)
					return
				}

				v, err := naPools.CallProxy(webHook.ServiceType, pcpClient.Call(webHook.FunName, r.URL.String(), r.Method, r.Header, string(body)), 120*time.Second)

				if err != nil {
					http.Error(w, "server error", http.StatusInternalServerError)
				}

				var wr WebHookResponse
				err = utils.ParseArg(v, &wr)
				if err != nil {
					http.Error(w, "server error", http.StatusInternalServerError)
				}

				w.WriteHeader(wr.Status)
				for name, values := range wr.Headers {
					for _, value := range values {
						w.Header().Set(name, value)
					}
				}

				w.Write([]byte(wr.Body))
			})
		}(webHook)
	}
}
