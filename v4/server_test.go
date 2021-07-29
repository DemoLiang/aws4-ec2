package v4

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// 官方测试：https://docs.aws.amazon.com/zh_cn/general/latest/gr/sigv4_signing.html
func TestCheckRequestWithAwsV4_Official(t *testing.T) {
	region, name := "us-east-1", "iam"
	key := &Key{
		AccessKey: "AKIDEXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
	}

	url := `https://iam.amazonaws.com?Action=ListUsers&Version=2010-05-08&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fiam%2Faws4_request&X-Amz-Date=20150830T123600Z&X-Amz-Expires=60&X-Amz-SignedHeaders=content-type%3Bhost&X-Amz-Signature=37ac2f4fde00b0ac9bd9eadeb459b1bbee224158d66e7ae5fcadb70b2d181d02`
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)
	req.Header.Set("content-type", `application/x-www-form-urlencoded; charset=utf-8`)

	_, _, err = CheckRequestWithAwsV4(req, key, region, name)
	assert.NoError(t, err)
}

func TestCheckRequestWithAwsV4(t *testing.T) {
	region, name := "universial", "query_api"
	key := &Key{
		AccessKey: "spiderman",
		SecretKey: "@C*u0NrTxs@Y89m#",
	}
	url := "http://localhost:9527/app"
	bodyType := "application/json"
	bodyStr := `{
  "jsonrpc": "2.0",
  "method": "getrawtransaction",
  "params": ["0xc7d805e937b92dd4905c689a931c7197cb5c4c45ee830ad17a33276c2f032d78", 1],
  "id": 1
}`
	req1, err := http.NewRequest("POST", url, strings.NewReader(bodyStr))
	assert.NoError(t, err)
	req1.Header.Set("Content-Type", bodyType)
	_, err = SignRequestWithAwsV4(req1, key, region, name)
	assert.NoError(t, err)

	req2, err := http.NewRequest("POST", url, strings.NewReader(bodyStr))
	assert.NoError(t, err)
	req2.Header.Set("Content-Type", bodyType)

	type args struct {
		req    *http.Request
		key    *Key
		region string
		name   string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "base test",
			args: args{
				req:    req1,
				key:    key,
				region: region,
				name:   name,
			},
			wantErr: false,
		},
		{name: "base test",
			args: args{
				req:    req2,
				key:    key,
				region: region,
				name:   name,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := CheckRequestWithAwsV4(tt.args.req, tt.args.key, tt.args.region, tt.args.name); (err != nil) != tt.wantErr {
				t.Errorf("CheckRequestWithAwsV4() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCheckRequestWithAwsV4_WithQueryString(t *testing.T) {
	region, name := "universial", "query_api"
	key := &Key{
		AccessKey: "spiderman",
		SecretKey: "@C*u0NrTxs@Y89m#",
	}
	url := "http://localhost:9527/app"
	bodyType := "application/json"
	bodyStr := `{
  "jsonrpc": "2.0",
  "method": "getrawtransaction",
  "params": ["0xc7d805e937b92dd4905c689a931c7197cb5c4c45ee830ad17a33276c2f032d78", 1],
  "id": 1
}`
	req1, err := http.NewRequest("POST", url, strings.NewReader(bodyStr))
	assert.NoError(t, err)
	req1.Header.Set("Content-Type", bodyType)
	_, err = SignRequestWithAwsV4UseQueryString(req1, key, region, name)
	assert.NoError(t, err)

	type args struct {
		req    *http.Request
		key    *Key
		region string
		name   string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "base test",
			args: args{
				req:    req1,
				key:    key,
				region: region,
				name:   name,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := CheckRequestWithAwsV4(tt.args.req, tt.args.key, tt.args.region, tt.args.name); (err != nil) != tt.wantErr {
				t.Errorf("CheckRequestWithAwsV4() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
