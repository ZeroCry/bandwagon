/*
Copyright 2017 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/gravitational/bandwagon/lib/gravity"
	"github.com/gravitational/trace"
)

// SetupHandlers configures API handlers.
func SetupHandlers() *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc("/api/info", noCaching(infoHandler)).Methods("GET")
	router.HandleFunc("/api/complete", noCaching(completeHandler)).Methods("POST")
	router.PathPrefix("/").Handler(http.FileServer(http.Dir(assetsDir)))
	return router
}

// infoHandler returns information about locally running site
//
//   GET /api/info
//
// Response:
//
//   {
//     "endpoints": [
//       {
//         "name": "Web",
//         "description": "Web application endpoint",
//         "addresses": ["http://192.168.0.1"]
//       }
//     ]
//   }
func infoHandler(w http.ResponseWriter, r *http.Request) {
	info, err := gravity.GetSiteInfo()
	if err != nil {
		replyError(w, err.Error())
		return
	}
	replyString(w, string(info))
}

type htppHandler func(http.ResponseWriter, *http.Request)

// noCaching tells proxies and browsers do not cache HTTP traffic
func noCaching(fn htppHandler) htppHandler {
	return func(w http.ResponseWriter, r *http.Request) {
		setNoCacheHeaders(w.Header())
		fn(w, r)
	}
}

// setNoCacheHeaders tells proxies and browsers do not cache the content
func setNoCacheHeaders(h http.Header) {
	h.Set("Cache-Control", "no-cache, max-age=0, must-revalidate, no-store")
	h.Set("Pragma", "no-cache")
	h.Set("Expires", "0")
}

// setIndexHTMLHeaders sets security header flags for main index.html page
func setIndexHTMLHeaders(h http.Header) {
	// Disable caching
	setNoCacheHeaders(h)

	// X-Frame-Options indicates that the page can only be displayed in iframe on the same origin as the page itself
	h.Set("X-Frame-Options", "SAMEORIGIN")

	// X-XSS-Protection is a feature of Internet Explorer, Chrome and Safari that stops pages
	// from loading when they detect reflected cross-site scripting (XSS) attacks.
	h.Set("X-XSS-Protection", "1; mode=block")

	// Once a supported browser receives this header that browser will prevent any communications from
	// being sent over HTTP to the specified domain and will instead send all communications over HTTPS.
	// It also prevents HTTPS click through prompts on browsers
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

	// Prevent web browsers from using content sniffing to discover a file’s MIME type
	h.Set("X-Content-Type-Options", "nosniff")

	// Set content policy flags,
	// 'unsafe-inline' attribute is fine for our SPA case
	var b bytes.Buffer
	fmt.Fprintf(&b, "base-uri 'self'")
	fmt.Fprintf(&b, "; script-src 'self' 'unsafe-inline'")
	fmt.Fprintf(&b, "; style-src 'self' 'unsafe-inline'")
	fmt.Fprintf(&b, "; img-src 'self' data: blob:")
	fmt.Fprintf(&b, "; child-src 'self'")

	h.Set("Content-Security-Policy", b.String())

	return
}

// completeHandler configures the site according to the data in the request
//
//   POST /api/complete
//
// Input:
//
//   CompleteRequest
//
// Response:
//
//   {
//     "message": "OK"
//   }
func completeHandler(w http.ResponseWriter, r *http.Request) {
	bytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		replyError(w, err.Error())
		return
	}

	var req CompleteRequest
	if err := json.Unmarshal(bytes, &req); err != nil {
		replyError(w, err.Error())
		return
	}

	err = gravity.CreateUser(req.Email, req.Password)
	if err != nil && !trace.IsAlreadyExists(err) {
		replyError(w, err.Error())
		return
	}

	err = gravity.CompleteInstall(req.Support)
	if err != nil {
		replyError(w, err.Error())
		return
	}

	replyOK(w)
}

// CompleteRequest is a request to complete site installation.
type CompleteRequest struct {
	// Email is the email of the admin user to create.
	Email string `json:"email"`
	// Password is the password of the admin user.
	Password string `json:"password"`
	// Support enables/disables remote support with Gravitational OpsCenter.
	Support bool `json:"support"`
}

const (
	// assetsDir is where static web assets are stored in the container we're running in
	assetsDir = "/opt/bandwagon/web/dist"
)
