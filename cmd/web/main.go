package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/voutasaurus/env"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func main() {
	logger := log.New(os.Stderr, "oauthtest: ", log.Llongfile|log.LstdFlags|log.LUTC)
	logger.Println("starting...")

	fatal := func(key string) {
		logger.Fatalf("expected environment variable %q to be set", key)
	}

	addr := ":" + env.Get("PORT").WithDefault("8080")

	// Your credentials should be obtained from the Google
	// Developer Console (https://console.developers.google.com).
	h := &oauthHandler{oauth2.Config{
		ClientID:     env.Get("OAUTH_CLIENT_ID").Required(fatal),
		ClientSecret: env.Get("OAUTH_CLIENT_SECRET").Required(fatal),
		RedirectURL:  env.Get("BASE_URL").Required(fatal) + "/oauth-google-redirect",
		Scopes:       []string{"profile", "email"},
		Endpoint:     google.Endpoint,
	}}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", h.handleLogin)
	mux.HandleFunc("/oauth-google-redirect", h.handleRedirect)

	logger.Println("serving on ", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

type oauthHandler struct {
	oauth2.Config
}

// handleLogin will redirect the user to Google's consent page to ask for
// permission for the scopes specified in h.Config.
//
// Use this when the user is not authenticated and the current GET request
// requires authorization. For POSTS you should just fail and expect the user
// to log on before posting.
func (h *oauthHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	// TODO: stuff current URL into state (so we can redirect back there
	// when we're done)
	// TODO: ensure protocol and domain are specified in the URL
	// r.URL.String()
	url := h.AuthCodeURL("state")
	http.Redirect(w, r, url, 307)
}

// handleRedirect gets the redirect from Google OAuth with the authorization
// codes, retrieves the scopes from the identity provider, issues a cookie, and
// redirects to the original URL.
func (h *oauthHandler) handleRedirect(w http.ResponseWriter, r *http.Request) {
	tok, err := h.Exchange(oauth2.NoContext, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, err.Error(), 401)
		return
	}
	client := h.Client(context.Background(), tok)
	_, err = client.Get("...") // TODO: get scopes?
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// TODO: encrypt and issue cookie
	home := "TODO: extract from state"
	http.Redirect(w, r, home, 307)
}
