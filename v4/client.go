package v4

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"os"
	"time"
)

// SignRequestWithAwsV4 signs an HTTP request with the given AWS keys for use on service
// use authorization header
func SignRequestWithAwsV4(req *http.Request, key *Key, region, name string) (sp *SignProcess, err error) {
	date := req.Header.Get(headKeyData)
	t := time.Now().UTC()
	if date != "" {
		t, err = time.Parse(http.TimeFormat, date)
		if err != nil {
			return
		}
	}
	req.Header.Set(headKeyXAmzDate, t.Format(iSO8601BasicFormat))

	sp = new(SignProcess)
	sp.Key = key.Sign(t, region, name)
	writeStringToSign(t, req, nil, sp, false, region, name)

	auth := bytes.NewBufferString(aws4HmacSha256Algorithm + " ")
	auth.Write([]byte("Credential=" + key.AccessKey + "/" + creds(t, region, name)))
	auth.Write([]byte{',', ' '})
	auth.Write([]byte("SignedHeaders="))
	writeHeaderList(req, nil, auth, false)
	auth.Write([]byte{',', ' '})
	auth.Write([]byte("Signature=" + hex.EncodeToString(sp.AllSHA256)))

	req.Header.Set(headKeyAuthorization, auth.String())
	return
}

// SignRequestWithAwsV4UseQueryString signs an HTTP request with the given AWS keys for use on service
// use query string
func SignRequestWithAwsV4UseQueryString(req *http.Request, key *Key, region, name string) (sp *SignProcess, err error) {
	date := req.Header.Get(headKeyData)
	t := time.Now().UTC()
	if date != "" {
		t, err = time.Parse(http.TimeFormat, date)
		if err != nil {
			return
		}
	}
	values := req.URL.Query()
	values.Set(queryKeyDate, t.Format(iSO8601BasicFormat))

	req.Header.Set(headKeyHost, req.Host)

	sp = new(SignProcess)
	sp.Key = key.Sign(t, region, name)

	values.Set(queryKeyAlgorithm, aws4HmacSha256Algorithm)
	values.Set(queryKeyCredential, key.AccessKey+"/"+creds(t, region, name))
	cc := bytes.NewBufferString("")
	writeHeaderList(req, nil, cc, false)
	values.Set(queryKeySignatureHeaders, cc.String())
	req.URL.RawQuery = values.Encode()

	writeStringToSign(t, req, nil, sp, false, region, name)
	values = req.URL.Query()
	values.Set(queryKeySignature, hex.EncodeToString(sp.AllSHA256))
	req.URL.RawQuery = values.Encode()

	return
}

// KeysFromEnvironment Initializes and returns a Keys using the AWS_ACCESS_KEY and AWS_SECRET_KEY
// environment variables.
func KeysFromEnvironment() *Key {
	return &Key{
		AccessKey: os.Getenv("AWS_ACCESS_KEY"),
		SecretKey: os.Getenv("AWS_SECRET_KEY"),
	}
}
