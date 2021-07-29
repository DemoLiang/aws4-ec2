package v4

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Authorization parameter
type Authorization struct {
	Algorithm      string   `json:"algorithm,omitempy"`
	Credential     string   `json:"credential,omitempy"`
	AccessKeyID    string   `json:"access_key_id,omitempy"`
	CredentialTime string   `json:"credential_time,omitempy"`
	Region         string   `json:"region,omitempy"`
	Name           string   `json:"name,omitempy"`
	SignedHeaders  []string `json:"signedHeaders,omitempy"`
	Signature      string   `json:"signature,omitempy"`

	initSignedHeadersMap bool
	signedHeadersMap     map[string]bool
}

/*
NewAuthorization include signing information
https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
https://docs.aws.amazon.com/zh_cn/general/latest/gr/sigv4_signing.html
*/
func NewAuthorization(req *http.Request) (a *Authorization, err error) {
	content := req.Header.Get(headKeyAuthorization)
	if len(content) > 0 {
		return newAuthorizationByHeader(content)
	}
	return newAuthorizationByQueryValues(req.URL.Query())
}

// DecodeCredential example: AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request
func (a *Authorization) DecodeCredential() (err error) {
	credentialList := strings.Split(a.Credential, "/")
	if len(credentialList) != 5 {
		err = fmt.Errorf("invalid Credential: %s", a.Credential)
		return
	}
	a.AccessKeyID = credentialList[0]
	a.CredentialTime = credentialList[1]
	a.Region = credentialList[2]
	a.Name = credentialList[3]
	return
}

func newAuthorizationByHeader(content string) (a *Authorization, err error) {
	list := strings.Split(content, " ")
	if len(list) != 4 {
		err = fmt.Errorf("invalid authorization: %s", content)
		return
	}
	a = &Authorization{
		Algorithm: list[0],
	}

	if a.Credential, err = getValueString("Credential=", list[1]); err != nil {
		return nil, err
	}
	if err = a.DecodeCredential(); err != nil {
		return nil, err
	}

	var signedHeadersStr string
	if signedHeadersStr, err = getValueString("SignedHeaders=", list[2]); err != nil {
		return nil, err
	}
	a.SignedHeaders = strings.Split(signedHeadersStr, ";")

	if a.Signature, err = getValueString("Signature=", list[3]); err != nil {
		return nil, err
	}
	return
}

func newAuthorizationByQueryValues(uValues url.Values) (a *Authorization, err error) {
	a = &Authorization{
		Algorithm:  uValues.Get(queryKeyAlgorithm),
		Credential: uValues.Get(queryKeyCredential),
		Signature:  uValues.Get(queryKeySignature),
	}

	if err = a.DecodeCredential(); err != nil {
		return nil, err
	}

	a.SignedHeaders = strings.Split(uValues.Get(queryKeySignatureHeaders), ";")
	return
}

func (a *Authorization) String() string {
	bs, _ := json.MarshalIndent(a, "", " ")
	return string(bs)
}

/*
Check details
https://docs.aws.amazon.com/general/latest/gr/sigv4-date-handling.html
https://docs.aws.amazon.com/zh_cn/general/latest/gr/sigv4-date-handling.html
*/
func (a *Authorization) Check(req *http.Request, region, name string) (t time.Time, err error) {
	if a.Algorithm != aws4HmacSha256Algorithm {
		err = fmt.Errorf("invalid sign algorithm: %s", a.Algorithm)
		return
	}

	dateStr := req.Header.Get(headKeyXAmzDate)
	if len(dateStr) == 0 {
		dateStr = req.URL.Query().Get(queryKeyDate)
	}
	if len(dateStr) == 0 {
		dateStr = req.Header.Get(headKeyData)
	}
	if len(dateStr) == 0 {
		err = fmt.Errorf("can not found date(header(%s,%s) and query(%s))", headKeyXAmzDate, headKeyData, queryKeyDate)
		return
	}
	t, err = time.Parse(iSO8601BasicFormat, dateStr)
	if err != nil {
		err = fmt.Errorf("can not parse time(%s) in header(%s,%s) as format %s", dateStr, headKeyXAmzDate, headKeyData, iSO8601BasicFormat)
		return
	}
	if !strings.HasPrefix(dateStr, a.CredentialTime) {
		err = fmt.Errorf("request time header(%s) do not match authorization's %s", dateStr, a.CredentialTime)
		return
	}
	if a.Region != region || a.Name != name {
		err = fmt.Errorf("invalid credential(region,name): %s", a.Credential)
		return
	}

	return
}

func (a *Authorization) containsSignedHeader(head string) bool {
	if !a.initSignedHeadersMap {
		a.signedHeadersMap = make(map[string]bool, len(a.SignedHeaders))
		for _, item := range a.SignedHeaders {
			a.signedHeadersMap[item] = true
		}
	}
	_, ok := a.signedHeadersMap[head]
	return ok
}

func getValueString(prefix, content string) (result string, err error) {
	if !strings.HasPrefix(content, prefix) {
		err = fmt.Errorf("can not cut content: [%s] with prefix: [%s]", content, prefix)
		return
	}
	result = strings.TrimSuffix(strings.TrimPrefix(content, prefix), ",")
	return
}

// SignProcess record the sign process
type SignProcess struct {
	Key           []byte
	Body          []byte
	BodySHA256    []byte
	Request       []byte
	RequestSHA256 []byte
	All           []byte
	AllSHA256     []byte
}

func (p *SignProcess) String() string {
	result := new(strings.Builder)
	fmt.Fprint(result, fmt.Sprintf("key(hex): %s\n\n", hex.EncodeToString(p.Key)))

	result.WriteString("------------ body begin ------------\n")
	result.Write(p.Body)
	result.Write(lf)
	result.WriteString("------------  body end  ------------\n")
	result.WriteString("body sha256: " + hex.EncodeToString(p.BodySHA256) + "\n")

	result.WriteString("------------ request begin ---------\n")
	result.Write(p.Request)
	result.Write(lf)
	result.WriteString("------------ request end -----------\n")
	result.WriteString("request sha256: " + hex.EncodeToString(p.RequestSHA256) + "\n")

	result.WriteString("------------ all begin -------------\n")
	result.Write(p.All)
	result.Write(lf)
	result.WriteString("------------ all end ---------------\n")
	result.WriteString("all sha256: " + hex.EncodeToString(p.AllSHA256) + "\n")
	// fmt.Fprint(result, fmt.Sprintf("all:\n%s\n", string(p.All)))
	// fmt.Fprint(result, fmt.Sprintf("all sha256: %s\n", hex.EncodeToString(p.AllSHA256)))
	return result.String()
}
