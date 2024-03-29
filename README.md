# aws4-ec2
aws4 ec2 access key and secret key sign http request



#  aws4 ec2签名校验

具体可以参考main函数示例

如果需要移除部分字段，只需要将对应的加密函数中的某些header字段移除即可，比如移除host字段：

```go
	requestData := bytes.NewBufferString("")
	//移除HOST字段
	//r.Header.Set(headKeyHost, r.Host)

	requestData.Write([]byte(r.Method))
	requestData.Write(lf)
```

## 参考示例：
```go
package main

import (
	"log"
	"net/http"

	aws4 "github.com/Demoliang/aws4-ec2/v4"
)

const (
	REGION  = "REGION-1"
	SERVICE = "SERVICE-1"
)

func main() {
	keys := aws4.Key{
		AccessKey: "access_key",
		SecretKey: "secret_key",
	}
	url := "http://127.0.0.1:8080/health"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(err)
	}

	_, err = aws4.SignRequestWithAwsV4(req, &keys, REGION, SERVICE)
	if err != nil {
		log.Printf("sign request error:%v", err)
		return
	}

	_, _, err = aws4.CheckRequestWithAwsV4(req, &keys, REGION, SERVICE)
	if err != nil {
		log.Printf("check request error:%v", err)
		return
	}
	log.Printf("sign success and check success")
}

```