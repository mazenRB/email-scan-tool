package main

import (
	"encoding/json"
	"fmt"
	"time"
)

//Struct for ScanReport
type ScanReport struct {
	Meta struct {
		FileInfo ScanReportFileInfo `json:"file_info"`
		URLInfo ScanReportURLInfo `json:"url_info"`
	} `json:"meta"`
	Data struct {
		Attributes ScanReportAttributes`json:"attributes"`
		Type  string `json:"type"`
		ID    string `json:"id"`
		Links ScanReportLinks `json:"links"`
	} `json:"data"`
}


func (sr *ScanReport) getSizeMB() (float32){
	return sr.Meta.FileInfo.getSizeMB()
}

func (sr *ScanReport) getSize() (int){
	return sr.Meta.FileInfo.getSize()
}

func (sr *ScanReport) getSha256() (string){
	return sr.Meta.FileInfo.getSha256()
}

func (sr *ScanReport) getSha1() (string){
	return sr.Meta.FileInfo.getSha1()
}

func (sr *ScanReport) getMd5() (string){
	return sr.Meta.FileInfo.getSha256()
}

func (sr *ScanReport) getURL() (string){
	return sr.Meta.URLInfo.getURL()
}

func (sr *ScanReport) getStatus() (string){
	return sr.Data.Attributes.getStatus()
}

func (sr *ScanReport) getDate() (Timestamp){
	return sr.Data.Attributes.getDate()
}

func (sr *ScanReport) getMalicous() (int){
	return sr.Data.Attributes.Stats.getMalicious()
}

func (sr *ScanReport) getSuspicious() (int){
	return sr.Data.Attributes.Stats.getSuspicious()
}

func (sr *ScanReport) getUndetected() (int){
	return sr.Data.Attributes.Stats.getUndetected()
}

func (sr *ScanReport) getHarmless() (int){
	return sr.Data.Attributes.Stats.getHarmless()
}

func (sr *ScanReport) getFailure() (int){
	return sr.Data.Attributes.Stats.getFailure()
}

func (sr *ScanReport) getResults() (map[string]ScanReportResults){
	return sr.Data.Attributes.getResults()
}

type ScanReportResults struct {
	Category      string `json:"category"`
	EngineName    string `json:"engine_name"`
	EngineUpdate  string `json:"engine_update"`
	EngineVersion string `json:"engine_version"`
	Method        string `json:"method"`
	Result        string `json:"result"`
}

func (srr *ScanReportResults) getCategory() (string){
	return srr.Category
}

func (srr *ScanReportResults) getEngineName() (string){
	return srr.EngineName
}

func (srr *ScanReportResults) getEngineUpdate() (string){
	return srr.EngineUpdate
}

func (srr *ScanReportResults) getEngineVersion() (string){
	return srr.EngineVersion
}

func (srr *ScanReportResults) getMethod() (string){
	return srr.Method
}

func (srr *ScanReportResults) getResult() (string){
	return srr.Result
}


type ScanReportAttributes struct {
	Date   Timestamp `json:"date"`
	Status string    `json:"status"`
	Stats  ScanReportStats `json:"stats"`
	Results map[string]ScanReportResults `json:"results"`
}

func (sra *ScanReportAttributes) getDate() (Timestamp){
	return sra.Date
}

func (sra *ScanReportAttributes) getStatus() (string){
	return sra.Status
}

func (sra *ScanReportAttributes) getStats() (ScanReportStats){
	return sra.Stats
}

func (sra *ScanReportAttributes) getResults() (map[string]ScanReportResults){
	return sra.Results
}

type ScanReportStats struct {
	Failure         int `json:"failure"`
	Harmless        int `json:"harmless"`
	Malicious       int `json:"malicious"`
	Suspicious      int `json:"suspicious"`
	Timeout         int `json:"timeout"`
	TypeUnsupported int `json:"type-unsupported"`
	Undetected      int `json:"undetected"`
}
func (srs *ScanReportStats) getFailure() (int){
	return srs.Failure
}
func (srs *ScanReportStats) getHarmless() (int){
	return srs.Harmless
}
func (srs *ScanReportStats) getMalicious() (int){
	return srs.Malicious
}
func (srs *ScanReportStats) getSuspicious() (int){
	return srs.Suspicious
}
func (srs *ScanReportStats) getTimeout() (int){
	return srs.Timeout
}
func (srs *ScanReportStats) getTypeUnsupported() (int){
	return srs.TypeUnsupported
}
func (srs *ScanReportStats) getUndetected() (int){
	return srs.Undetected
}

type ScanReportLinks struct {
	Item string `json:"item"`
	Self string `json:"self"`
}

func (srl *ScanReportLinks) getItem() (string){
	return srl.Item
}

func (srl *ScanReportLinks) getSelf() (string){
	return srl.Self
}

type ScanReportFileInfo struct {
	Sha256 string `json:"sha256"`
	Sha1   string `json:"sha1"`
	Md5    string `json:"md5"`
	Size   int    `json:"size"` 
	SizeMB float32 
}

func (srfi *ScanReportFileInfo) setSizeMB(size float32) {
	srfi.SizeMB = size
}

func (srfi *ScanReportFileInfo) getSha256() (string){
	return srfi.Sha256
}
func (srfi *ScanReportFileInfo) getSha1() (string){
	return srfi.Sha1
}
func (srfi *ScanReportFileInfo) getMd5() (string){
	return srfi.Md5
}
func (srfi *ScanReportFileInfo) getSize() (int){
	return srfi.Size
}
func (srfi *ScanReportFileInfo) getSizeMB() (float32){
	return float32(srfi.Size / 1048576.000)
}

type ScanReportURLInfo struct {
	URL string `json:"url"`
	ID  string `json:"id"`
}

func (srui *ScanReportURLInfo) getURL() (string){
	return srui.URL
}
func (srui *ScanReportURLInfo) getID() (string){
	return srui.ID
}


// Time Object for Humand Readability
type Timestamp struct {
	time.Time
}

// UnmarshalJSON decodes an int64 timestamp into a time.Time object
func (p *Timestamp) UnmarshalJSON(bytes []byte) error {
	// 1. Decode the bytes into an int64
	var raw int64
	err := json.Unmarshal(bytes, &raw)

	if err != nil {
		fmt.Printf("error decoding timestamp: %s\n", err)
		return err
	}

	// 2 - Parse the unix timestamp
	p.Time = time.Unix(raw, 0)
	return nil
}