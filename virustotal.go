package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

var apikey = "6d017b583d595aa9f42a2d04262cefab373e360a0554e77b8c7d51705cfd9419"


const (
	default_endpoint_url        = "https://www.virustotal.com/api/v3/"
	default_files_url         = default_endpoint_url + "files"
	default_domain_upload_url = default_endpoint_url + "urls"
	default_domain_report_url = default_endpoint_url + "analyses/"
)

const (
	// Maximum size of payloads posted to VirusTotal's API endpoints.
	maxPayloadSize = 30 * 1024 * 1024 // 30 MB
	// Maximum file size that can scanned by VirusTotal.
	maxFileSize = 650 * 1024 * 1024 // 650 MB
)

const (
	DOMAIN_REPORT = "URL"
	FILE_REPORT   = "FILE"
)



/* Upload URL to Scan */
func uploadDomain(domain string) (id string) {
	//API URL
	endpoint_url := ""

	//Check if url is empty
	if len(domain) <= 0 {
		panic("No URL or IP")
	}

	//Define Values
	endpoint_url = default_domain_upload_url // URL für URL/IP Scan Reports
	payload := strings.NewReader("url=" + domain)

	//Define Request
	req, err := http.NewRequest("POST", endpoint_url, payload)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	//Define Header
	req.Header.Add("Accept", "application/json")
	req.Header.Add("x-apikey", apikey)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	//Execute Request
	res, err := http.DefaultClient.Do(req)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	//Close Request
	defer res.Body.Close()

	//Read Body
	body, err := ioutil.ReadAll(res.Body)

	if err != nil {
		panic(err)
	}

	//return ID

	reportID := gjson.Get(string(body), "data.id").String()

	if len(reportID) <= 0 {
		panic(body)
	}
	return reportID
}

/* Upload URL to Scan */
func uploadFileToVST(object io.Reader, fheader *multipart.FileHeader) (id string, err error) {
	//API URL
	endpoint_url := ""

	//Check if file is empty
	if object == nil {
		return "", errors.New("No File found - Func: uploadFileToVST")
	}

	endpoint_url = default_files_url // URL für File Reports

	//Prepare Payload
	payload := bytes.Buffer{}

	//Create Multipart-Writer and random Boundary for Request
	w := multipart.NewWriter(&payload)
	//Create io.Writer and add Form-Data Header for Filename
	f, err := w.CreateFormFile("file", fheader.Filename)

	//Check is Error occured
	if err != nil {
		return "", errors.New("Error uploading file - Func: uploadFileToVST")
	}

	//Get Payload Size and Copy file into io.Writer -> Filedate is now in payload
	payloadSize, err := io.Copy(f, object)

	if payloadSize > maxFileSize {
		return "", errors.New("Error Datei zu groß zum Upload - Func: uploadFileToVST")
	} else if payloadSize > maxPayloadSize {
		return "", errors.New("Error Datei überschreitet die maxmimale Payload Größe - Func: uploadFileToVST")
	}

	headers := map[string]string{"Content-Type": w.FormDataContentType()}

	//Define Request
	req, err := http.NewRequest("POST", endpoint_url, &payload)
	if err != nil {
		return "", err
	}

	//Define Header
	req.Header.Add("Accept", "application/json")
	req.Header.Add("x-apikey", apikey)

	if headers != nil {
		for k, v := range headers {
			req.Header.Add(k, v)
		}
	}

	//Execute Request
	res, err := http.DefaultClient.Do(req)

	if err != nil {
		fmt.Println(err.Error())
		return "", err
	}

	//Close Request
	defer res.Body.Close()

	//Read Body
	body, err := ioutil.ReadAll(res.Body)

	if err != nil {
		return "",err
	}

	//return ID

	reportID := gjson.Get(string(body), "data.id").String()

	if len(reportID) <= 0 {
		return "",errors.New("No Report ID found - Func: uploadFileToVST")
	}
	return reportID, nil
}

func getScanReport(id string) (result *ScanReport) {
	status := ""
	var body []byte
	endpoint_url := ""

	//Check if id ist not null
	if len(id) <= 0 {
		panic("No ID to get Report in 'getScanReport'")
	}

	endpoint_url = default_domain_report_url + id

	//Define Request
	req, err := http.NewRequest("GET", endpoint_url, nil)
	if err != nil {
		panic(err)
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("x-apikey", apikey)

	for status != "completed" {
		
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			panic(err)
		}

		defer res.Body.Close()

		body, err = ioutil.ReadAll(res.Body)

		if err != nil {
			panic(err)
		}

		status = gjson.Get(string(body), "data.attributes.status").String()
		fmt.Println(gjson.Get(string(body), "data.attributes.status").String())
		if status != "completed" {
			time.Sleep(10 * time.Second)
		}
	}

	//Convert Body to JSON
	var jRes = new(ScanReport)

	//Workaround -> Using Functions in Template not working
	jRes.Meta.FileInfo.setSizeMB(float32(jRes.getSize()) / 1048576.000)

	err = json.Unmarshal(body, &jRes)

	if err != nil {
		panic(err)
	}

	return jRes
}

func generateSHA256(file multipart.File) (result string) {

	//Check if File is null
	if file == nil {
		panic("No File to generate Hash")
	}

	//Create SHA256 Generator
	h := sha256.New()

	//Generate Hash
	filehash, err := io.Copy(h, file)

	if err != nil {
		panic(err)
	}

	stringHash := strconv.FormatInt(filehash, 10)

	return stringHash
}

