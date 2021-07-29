// Package v4 signs HTTP requests as prescribed in
// http://docs.amazonwebservices.com/general/latest/gr/signature-version-4.html
package v4

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const iSO8601BasicFormat = "20060102T150405Z"
const iSO8601BasicFormatShort = "20060102"

var lf = []byte{'\n'}

// Key holds a set of Amazon Security Credentials.
type Key struct {
	AccessKey string
	SecretKey string
}

/*
Sign derive a signing key for Signature Version 4
https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html
https://docs.aws.amazon.com/zh_cn/general/latest/gr/signature-v4-examples.html
*/
func (k *Key) Sign(t time.Time, region, name string) []byte {
	h := ghmac([]byte("AWS4"+k.SecretKey), []byte(t.Format(iSO8601BasicFormatShort)))
	h = ghmac(h, []byte(region))
	h = ghmac(h, []byte(name))
	h = ghmac(h, []byte("aws4_request"))
	return h
}

func writeStringToSign(
	t time.Time,
	r *http.Request,
	a *Authorization,
	sp *SignProcess,
	isServer bool,
	region, name string) {
	lastData := bytes.NewBufferString(aws4HmacSha256Algorithm)
	lastData.Write(lf)

	lastData.Write([]byte(t.Format(iSO8601BasicFormat)))
	lastData.Write(lf)

	lastData.Write([]byte(creds(t, region, name)))
	lastData.Write(lf)

	writeRequest(r, a, sp, isServer)
	lastData.WriteString(hex.EncodeToString(sp.RequestSHA256))
	// fmt.Fprintf(lastData, "%x", sp.RequestSHA256)

	sp.All = lastData.Bytes()
	sp.AllSHA256 = ghmac(sp.Key, sp.All)
}

func writeRequest(r *http.Request, a *Authorization, sp *SignProcess, isServer bool) {
	requestData := bytes.NewBufferString("")
	r.Header.Set(headKeyHost, r.Host)

	requestData.Write([]byte(r.Method))
	requestData.Write(lf)

	writeURI(r, requestData)
	requestData.Write(lf)

	writeQuery(r, requestData)
	requestData.Write(lf)

	writeHeader(r, a, requestData, isServer)
	requestData.Write(lf)
	requestData.Write(lf)

	writeHeaderList(r, a, requestData, isServer)
	requestData.Write(lf)

	writeBody(r, requestData, sp)

	sp.Request = requestData.Bytes()
	sp.RequestSHA256 = gsha256(sp.Request)
}

func writeURI(r *http.Request, requestData io.Writer) {
	path := r.URL.RequestURI()
	if r.URL.RawQuery != "" {
		path = path[:len(path)-len(r.URL.RawQuery)-1]
	}
	slash := strings.HasSuffix(path, "/")
	//path = filepath.Clean(path)
	if path != "/" && slash {
		path += "/"
	}
	_, _ = requestData.Write([]byte(path))
}

func writeQuery(r *http.Request, requestData io.Writer) {
	var a []string
	for k, vs := range r.URL.Query() {
		k = url.QueryEscape(k)
		if k == queryKeySignature {
			continue
		}
		for _, v := range vs {
			if v == "" {
				a = append(a, k)
			} else {
				v = url.QueryEscape(v)
				a = append(a, k+"="+v)
			}
		}
	}
	sort.Strings(a)
	for i, s := range a {
		if i > 0 {
			_, _ = requestData.Write([]byte{'&'})
		}
		_, _ = requestData.Write([]byte(s))
	}
}

func writeHeader(r *http.Request, au *Authorization, requestData *bytes.Buffer, isServer bool) {
	a := make([]string, 0)
	for k, v := range r.Header {
		if isServer {
			if !au.containsSignedHeader(strings.ToLower(k)) {
				continue
			}
		}
		sort.Strings(v)
		a = append(a, strings.ToLower(k)+":"+strings.Join(v, ","))
	}
	sort.Strings(a)
	for i, s := range a {
		if i > 0 {
			_, _ = requestData.Write(lf)
		}
		_, _ = requestData.WriteString(s)
	}
}

func writeHeaderList(r *http.Request, au *Authorization, requestData io.Writer, isServer bool) {
	a := make([]string, 0)
	for k := range r.Header {
		if isServer {
			if !au.containsSignedHeader(strings.ToLower(k)) {
				continue
			}
		}
		a = append(a, strings.ToLower(k))
	}
	sort.Strings(a)
	for i, s := range a {
		if i > 0 {
			_, _ = requestData.Write([]byte{';'})
		}
		_, _ = requestData.Write([]byte(s))
	}
}

func writeBody(r *http.Request, requestData io.StringWriter, sp *SignProcess) {
	var b []byte
	// If the payload is empty, use the empty string as the input to the SHA256 function
	// http://docs.amazonwebservices.com/general/latest/gr/sigv4-create-canonical-request.html
	if r.Body == nil {
		b = []byte("")
	} else {
		var err error
		b, err = ioutil.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}
		r.Body = ioutil.NopCloser(bytes.NewBuffer(b))
	}
	sp.Body = b

	sp.BodySHA256 = gsha256(b)
	_, _ = requestData.WriteString(hex.EncodeToString(sp.BodySHA256))
}

func creds(t time.Time, region, name string) string {
	return t.Format(iSO8601BasicFormatShort) + "/" + region + "/" + name + "/aws4_request"
}

func gsha256(data []byte) []byte {
	h := sha256.New()
	_, _ = h.Write(data)
	return h.Sum(nil)
}

func ghmac(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(data)
	return h.Sum(nil)
}
