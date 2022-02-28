// main.go

package main

import (
	"fmt"
	"log"
	"mime"
	"net/http"
	"net/mail"
	"strings"

	"github.com/gin-gonic/gin"
)

var router *gin.Engine

func main() {
	// Set the router as the default one provided by Gin
	router = gin.Default()

	// Process the templates at the start so that they don't have to be loaded
	// from the disk again. This makes serving HTML pages very fast.
	router.LoadHTMLGlob("templates/*")

	// Initialize the routes
	initializeRoutes()

	// Start serving the application
	err := router.Run()

	if err != nil {
		fmt.Println(err.Error())
	}

}

func scanFile(c *gin.Context) {
	file, fHeader, err := c.Request.FormFile("file")
	if err != nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("file err : %s", err.Error()))
		panic(err)
	}

	id, err := uploadFileToVST(file, fHeader)

	if err != nil {
		//Show Result
		c.HTML(
			// Set the HTTP status to 200 (OK)
			http.StatusBadRequest,
			// Use the url.html template
			"error.html",
			// Pass the data that the page uses (in this case, 'title')
			gin.H{
				"title": "Error Page",
				"err":   err.Error(),
			},
		)
	} else {
		//Get Result
		res := getScanReport(id)
		//Show Result
		c.HTML(
			// Set the HTTP status to 200 (OK)
			http.StatusOK,
			// Use the url.html template
			"url-result.html",
			// Pass the data that the page uses (in this case, 'title')
			gin.H{
				"title":    "File result",
				"id":       id,
				"result":   res,
				"filename": fHeader.Filename,
			},
		)
	}

}

func scanUrl(c *gin.Context) {
	c.Request.ParseForm()
	//Get Url from Form
	url := c.Request.Form["url"][0]

	//Upload Url to Scan (No Errors in this function implemented)
	id := uploadDomain(url)

	//Get Result
	res := getScanReport(id)

	//Show Result
	c.HTML(
		// Set the HTTP status to 200 (OK)
		http.StatusOK,
		// Use the url.html template
		"url-result.html",
		// Pass the data that the page uses (in this case, 'title')
		gin.H{
			"title":  "URL/IP Results",
			"id":     id,
			"result": res,
		},
	)

}

func parseMailHeader(c *gin.Context) {
	//parse the input
	c.Request.ParseForm()
	// read the input from the textarea with the name "mail" in mail-header.html
	header_input := c.Request.Form["mail"]

	
	//join the input
	temp := strings.Join(header_input, "\n")

	//NewReader returns a new Reader reading from s.
	// It is similar to bytes.NewBufferString but more efficient and read-only
	r := strings.NewReader(temp)
	//ReadMessage reads a message from r. The headers are parsed
	msg, err := mail.ReadMessage(r)

	if err != nil {
		//panic(err)
		fmt.Println(err)
	}
	// Header from the Message
	header := msg.Header

	// Safe the results in Variables
	headerdate := header.Get("Date")
	headerreturnpath := header.Get("Return-Path")
	headerfrom := header.Get("From")
	headerto := header.Get("To")
	headersubject := header.Get("Subject")
	headerreceived := header.Get("X-Originating-Ip")
	headerspf_tmp := header.Get("Received-SPF")

	// Split the SPF - Info
	headerspf := strings.Split(headerspf_tmp, " (")

	if err != nil {
		log.Fatal(err)
	}

	// Subject is often encoded in RFC 2047, so we decoded it
	// If the subject is not encoded it makes no difference to the result
	dec := new(mime.WordDecoder)
	// Overwrite the variable "headersubject"
	headersubject, err = dec.DecodeHeader(headersubject)

	if err != nil {
		panic(err)
	}
	// -------------------------------------------
	// Link to a new gin Context HTML Site
	c.HTML(
		// Set the HTTP status to 200 (OK)
		http.StatusOK,
		// Use the url.html template
		"header-result.html",
		// Pass the data that the page uses (in this case, 'title')
		gin.H{
			"title":    "Header results",
			"Date":     headerdate,
			"RPath":    headerreturnpath,
			"From":     headerfrom,
			"To":       headerto,
			"Subject":  headersubject,
			"Received": headerreceived,
			"SPF":      headerspf[0],
		},
	)

}
