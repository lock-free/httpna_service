package mid

import (
	"encoding/json"
	"github.com/lock-free/gopcp"
	"net/http"
	"net/url"
)

type PcpHttpResponse struct {
	Data   interface{} `json:"text"`
	Errno  int         `json:"errno"`
	ErrMsg string      `json:"errMsg"`
}

func ResponseToBytes(pcpHttpRes PcpHttpResponse) []byte {
	bytes, err := gopcp.JSONMarshal(pcpHttpRes)

	if err != nil {
		bytes, _ = json.Marshal(ErrorToResponse(err))
	}

	return bytes
}

type MidFunType = func(http.ResponseWriter, *http.Request, interface{}) (interface{}, error)

// define http error type
type HttpError struct {
	Errno  int
	ErrMsg string
}

func (err *HttpError) Error() string {
	return err.ErrMsg
}

func ErrorToResponse(err error) PcpHttpResponse {
	code := 530 // default error code
	if err, ok := err.(*HttpError); ok {
		code = err.Errno
	}
	return PcpHttpResponse{nil, code, err.Error()}
}

func GetPcpMid(sandbox *gopcp.Sandbox) MidFunType {
	pcpServer := gopcp.NewPcpServer(sandbox)

	return func(w http.ResponseWriter, r *http.Request, attachment interface{}) (arr interface{}, err error) {
		var pcpHttpRes PcpHttpResponse
		var rawQuery string

		if r.Method == "GET" {
			rawQuery, err = url.QueryUnescape(r.URL.RawQuery)
			if err == nil {
				// parse url query
				err = json.Unmarshal([]byte(rawQuery), &arr)
			}
		} else if r.Method == "POST" || r.Method == "PUT" { // POST, PUT
			// get post body
			arr, err = GetJsonBody(r)
		} else {
			err = &HttpError{541, "Unexpected http method. Expect Get or POST or PUT."}
		}

		if err != nil {
			// write error back
			pcpHttpRes = ErrorToResponse(err)
			w.Write(ResponseToBytes(pcpHttpRes))
			return
		}

		pcpServer.ExecuteJsonObj(arr, attachment)

		return
	}
}

func FlushPcpFun(pcpFun gopcp.GeneralFun) gopcp.GeneralFun {
	return func(args []interface{}, attachment interface{}, pcpServer *gopcp.PcpServer) (ret interface{}, err error) {
		ret, err = pcpFun(args, attachment, pcpServer)

		var pcpHttpRes PcpHttpResponse
		if err != nil {
			pcpHttpRes = ErrorToResponse(err)
		} else {
			pcpHttpRes = PcpHttpResponse{ret, 0, ""}
		}

		httpAttachment := attachment.(HttpAttachment)
		httpAttachment.W.Write(ResponseToBytes(pcpHttpRes))

		return
	}
}

type HttpAttachment struct {
	W http.ResponseWriter
	R *http.Request
}

func GetJsonBody(r *http.Request) (arr interface{}, err error) {
	decorder := json.NewDecoder(r.Body)
	err = decorder.Decode(&arr)
	return
}
