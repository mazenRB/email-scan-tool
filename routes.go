// routes.go

package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func initializeRoutes() {

	//GET

	// Handle the index route
	router.GET("/", func(c *gin.Context) {

		// Call the HTML method of the Context to render a template
		c.HTML(
			// Set the HTTP status to 200 (OK)
			http.StatusOK,
			// Use the index.html template
			"index.html",
			// Pass the data that the page uses (in this case, 'title')
			gin.H{
				"title": "Home Page",
			},
		)

	})

	router.GET("/uploadFile", func(c *gin.Context) {

		// Call the HTML method of the Context to render a template
		c.HTML(
			// Set the HTTP status to 200 (OK)
			http.StatusOK,
			// Use the select_file.html template
			"select_file.html",
			// Pass the data that the page uses (in this case, 'title')
			gin.H{
				"title": "Upload File",
			},
		)

	})

	router.GET("/url-scan", func(c *gin.Context) {

		// Call the HTML method of the Context to render a template
		c.HTML(
			// Set the HTTP status to 200 (OK)
			http.StatusOK,
			// Use the url.html template
			"url.html",
			// Pass the data that the page uses (in this case, 'title')
			gin.H{
				"title": "Url Scan",
			},
		)

	})

	router.GET("/mail-header", func(c *gin.Context) {

		// Call the HTML method of the Context to render a template
		c.HTML(
			// Set the HTTP status to 200 (OK)
			http.StatusOK,
			// Use the url.html template
			"mail-header.html",
			// Pass the data that the page uses (in this case, 'title')
			gin.H{
				"title": "Mail Header Analyzer",
			},
		)

	})

	//POST
	router.POST("/upload", scanFile)
	router.POST("/url-scan/result", scanUrl)
	router.POST("/parse-result", parseMailHeader)

	//FILESYSTEM
	router.StaticFS("/file", http.Dir("public"))
}
