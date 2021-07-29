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
