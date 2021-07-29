package v4

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

// CheckRequestWithAwsV4 runs for server
func CheckRequestWithAwsV4(req *http.Request, key *Key, region, name string) (a *Authorization, sp *SignProcess, err error) {
	if a, err = NewAuthorization(req); err != nil {
		return
	}

	var t time.Time
	if t, err = a.Check(req, region, name); err != nil {
		return
	}

	sp = new(SignProcess)
	sp.Key = key.Sign(t, region, name)

	writeStringToSign(t, req, a, sp, true, region, name)
	result := hex.EncodeToString(sp.AllSHA256)

	if a.Signature != result {
		fmt.Println(sp)
		err = fmt.Errorf("awsv4 check faild. expected: %s, got: %s", a.Signature, result)
		return
	}

	return
}

// CheckRequestWithAwsV4KeyMaps runs for server
func CheckRequestWithAwsV4KeyMaps(req *http.Request, keys map[string]string, region, name string) (a *Authorization, sp *SignProcess, err error) {
	if a, err = NewAuthorization(req); err != nil {
		return
	}

	secretKey, ok := keys[a.AccessKeyID]
	if !ok {
		err = fmt.Errorf("access key id: [%s] is not supported", a.AccessKeyID)
		return
	}
	key := &Key{
		AccessKey: a.AccessKeyID,
		SecretKey: secretKey,
	}

	var t time.Time
	if t, err = a.Check(req, region, name); err != nil {
		return
	}

	sp = new(SignProcess)
	sp.Key = key.Sign(t, region, name)

	writeStringToSign(t, req, a, sp, true, region, name)
	result := hex.EncodeToString(sp.AllSHA256)

	if a.Signature != result {
		fmt.Println(sp)
		err = fmt.Errorf("awsv4 check faild. expected: %s, got: %s", a.Signature, result)
		return
	}

	return
}
