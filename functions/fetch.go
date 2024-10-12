package functions

import (
	"bytes"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"slices"
	"strings"
)

// var IgnoreProxy bool

var DefaultCient = new(http.Client)

// func InitClient(timeout int) *http.Client {
// 	transport := http.DefaultTransport
//
// 	if IgnoreProxy {
// 		transport.(*http.Transport).Proxy = nil
// 	}
//
// 	return &http.Client{
// 		Timeout:   time.Second * time.Duration(timeout),
// 		Transport: transport,
// 	}
// }

var EmptyHeaders = map[string]string{}

const BrowserUserAgent = "TinyPush Go Service"

func Fetch(_url string, _method string, _body []byte, _headers map[string]string) (*http.Response, []byte, error) {
	var body io.Reader

	if strings.ToUpper(_method) == "POST" {
		body = bytes.NewReader(_body)
	} else {
		body = nil
	}
	req, err := http.NewRequest(_method, _url, body)
	if err != nil {
		log.Println("fetch:", err)
		return nil, nil, err
	}
	req.Header.Set("User-Agent", BrowserUserAgent)
	if slices.Contains([]string{"POST", "PUT", "PATCH"}, strings.ToUpper(_method)) {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	for k, v := range _headers {
		req.Header.Set(k, v)
	}

	resp, err := DefaultCient.Do(req)
	if err != nil {
		log.Println("fetch:", err)
		return nil, nil, err
	}
	defer resp.Body.Close()
	response, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("fetch:", err)
		return nil, nil, err
	}
	//log.Println(_url)
	//log.Println(string(response[:]))

	return resp, response, err
}

type MultipartBodyBinaryFileType struct {
	Fieldname string
	Filename  string
	Binary    []byte
}

func MultipartBodyBuilder(_body map[string]any, files ...MultipartBodyBinaryFileType) ([]byte, string, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	for k, v := range _body {
		part, _ := writer.CreateFormField(k)
		part.Write([]byte(v.(string)))
	}

	for _, _file := range files {
		part, err := writer.CreateFormFile(_file.Fieldname, _file.Filename)
		if err != nil {
			return nil, "", err
		}
		part.Write(_file.Binary)
	}

	err := writer.Close()
	if err != nil {
		return nil, "", err
	}
	return body.Bytes(), writer.FormDataContentType(), nil
}
