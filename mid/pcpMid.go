package mid

import (
	"bytes"
	"encoding/json"
	"github.com/idata-shopee/gopcp"
	"net/http"
	"net/url"
)

type PcpHttpResponse struct {
	Data   interface{} `json:"text"`
	Errno  int         `json:"errno"`
	ErrMsg string      `json:"errMsg"`
}

func JSONMarshal(t interface{}) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(t)
	return buffer.Bytes(), err
}

func ResponseToBytes(pcpHttpRes PcpHttpResponse) []byte {
	bytes, jerr := JSONMarshal(pcpHttpRes)

	if jerr != nil {
		ret, _ := json.Marshal(ErrorToResponse(jerr))
		return ret
	} else {
		return bytes
	}
}

type MidFunType = func(http.ResponseWriter, *http.Request, interface{}) (interface{}, error)

type HttpError struct {
	Errno  int
	ErrMsg string
}

func (he *HttpError) Error() string {
	return he.ErrMsg
}

func ErrorToResponse(err error) PcpHttpResponse {
	code := 530
	if err, ok := err.(*HttpError); ok {
		code = err.Errno
	}
	return PcpHttpResponse{nil, code, err.Error()}
}

func GetPcpMid(sandbox *gopcp.Sandbox) MidFunType {
	pcpServer := gopcp.NewPcpServer(sandbox)

	return func(w http.ResponseWriter, r *http.Request, attachment interface{}) (interface{}, error) {
		var pcpHttpRes PcpHttpResponse
		var arr interface{}
		var err error = nil
		var rawQuery string
		var ret interface{}

		if r.Method == "GET" {
			rawQuery, err = url.QueryUnescape(r.URL.RawQuery)
			if err == nil {
				// parse url query
				err = json.Unmarshal([]byte(rawQuery), &arr)
			}
		} else {
			// get post body
			arr, err = GetJsonBody(r)
		}

		if err != nil {
			pcpHttpRes = ErrorToResponse(err)
		} else {
			ret, err = pcpServer.ExecuteJsonObj(arr, attachment)

			if err != nil {
				pcpHttpRes = ErrorToResponse(err)
			} else {
				pcpHttpRes = PcpHttpResponse{ret, 0, ""}
			}
		}

		w.Write(ResponseToBytes(pcpHttpRes))
		return arr, err
	}
}

func GetJsonBody(r *http.Request) (interface{}, error) {
	decorder := json.NewDecoder(r.Body)
	var arr interface{}
	if derr := decorder.Decode(&arr); derr != nil {
		return nil, derr
	} else {
		return arr, nil
	}
}
