// AWS Version 4 signing example
// EC2 API (DescribeRegions)
/*
See: http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
This version makes a GET request and passes the signature
in the Authorization header. */
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

func main() {
	// ************* REQUEST VALUES *************
	method := "GET"
	service := "ec2"
	host := "ec2.amazonaws.com"
	region := "us-east-1"
	endpoint := "https://ec2.amazonaws.com"
	requestParameters := "Action=DescribeRegions&Version=2013-10-15"

	// Read AWS access key from env. variables or configuration file. Best practice is NOT
	// to embed credentials in code.
	accessKey := "AKISAMPLEKEY" // AWS Access Key
	secretKey := "123SecretKey" // AWS Secret Key

	// Create a date for headers and the credential string
	dateStamp := time.Now().UTC().Format("20060102")
	amzDate := time.Now().UTC().Format("20060102T150405Z")

	// ************* TASK 1: CREATE A CANONICAL REQUEST *************
	// http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html


	// string (use '/' if no path)
	canonicalUri := "/"
	canonicalQueryString := requestParameters
	canonicalHeaders := "host:" + host + "\n" + "x-amz-date:" + amzDate + "\n"
	signedHeaders := "host;x-amz-date"
	payloadHash := doSha256("")

	canonicalRequest := method + "\n" + canonicalUri + "\n" + canonicalQueryString + "\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHash

	// ************* TASK 2: CREATE THE STRING TO SIGN*************
	// Match the algorithm to the hashing algorithm you use, either SHA-1 or
	// SHA-256 (recommended)
	algo := "AWS4-HMAC-SHA256"
	credentialScope := dateStamp + "/" + region + "/" + service + "/" + "aws4_request"
	stringToSign := algo + "\n" + amzDate + "\n" + credentialScope + "\n" + doSha256(canonicalRequest)

	// ************* TASK 3: CALCULATE THE SIGNATURE *************
	// Create the signing key using the function defined above.
	signingKey := getSignature(secretKey, dateStamp, region, service)

	signature := hex.EncodeToString(HmacSHA256(stringToSign, []byte(signingKey)))
	fmt.Println("signature: ", signature)

	// ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
	// The signing information can be either in a query string value or in
	// a header named Authorization. This code shows how to use a header.
	// Create authorization header and add to request headers
	authHeader := algo + " " + "Credential=" + accessKey + "/" + credentialScope + ", " + "SignedHeaders=" + signedHeaders + ", " +
		"Signature=" + signature

	// ************* SEND THE REQUEST *************
	request, err := http.NewRequest("GET", endpoint+"?"+canonicalQueryString, nil)
	if err != nil {
		fmt.Println("Error while generating request", err)
	}
	request.Header.Set("x-amz-date", amzDate)
	request.Header.Set("Authorization", authHeader)

	fmt.Println("request", request)
	client := http.Client{
		Timeout: 0, //set value accordingly
	}
	response, err := client.Do(request)
	if err != nil {
		fmt.Println("Error occurred while sending request", err)
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println("Error while reading body :", err)
	}
	fmt.Println("Body : ", string(body))
}

func doSha256(data string) string {
	hash := sha256.New()
	if _, err := io.Copy(hash, strings.NewReader(data)); err != nil {
		log.Fatal("Error while generating SHA256", err)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func HmacSHA256(data string, key []byte) []byte {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(data))
	return h.Sum(nil)
}

func getSignature(key string, dateStamp string, regionName string, serviceName string) []byte {
	kDate := HmacSHA256(dateStamp, []byte("AWS4"+key))
	kRegion := HmacSHA256(regionName, []byte(kDate))
	kService := HmacSHA256(serviceName, []byte(kRegion))
	kSigning := HmacSHA256("aws4_request", []byte(kService))
	return kSigning

}
