package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/voutasaurus/env"

	"golang.org/x/crypto/nacl/secretbox"
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

	// TODO: use public / private key pairs and register them via shared
	// config so that multiple oauth backends can take redirects with each
	// other's login states. (solve key bootstrapping)
	// NOTE: right now this only works with a single oauth backend.

	stateKey, err := newKey()
	if err != nil {
		logger.Fatalf("error generating state key: %v", err)
	}

	// Your credentials should be obtained from the Google
	// Developer Console (https://console.developers.google.com).
	h := &oauthHandler{
		Config: oauth2.Config{
			ClientID:     env.Get("OAUTH_CLIENT_ID").Required(fatal),
			ClientSecret: env.Get("OAUTH_CLIENT_SECRET").Required(fatal),
			RedirectURL:  "https://" + env.Get("DOMAIN").Required(fatal) + "/oauth-google-redirect",
			Scopes:       []string{"profile", "email"},
			Endpoint:     google.Endpoint,
		},
		stateKey: stateKey,

		// TODO: create a way of sharing cookieKey with multiple
		// backends (maybe public/private).
		// Note: every domain should have a different key. Otherwise it
		// can be copied and used across domains.
		cookieKey: stateKey,

		domain: env.Get("DOMAIN").Required(fatal),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handleHome)
	mux.HandleFunc("/login", h.handleLogin)
	mux.HandleFunc("/oauth-google-redirect", h.handleRedirect)

	logger.Println("serving on ", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

type oauthHandler struct {
	oauth2.Config
	stateKey  *[32]byte
	cookieKey *[32]byte
	domain    string
}

func (h *oauthHandler) handleHome(w http.ResponseWriter, r *http.Request) {
	id, err := getCookie(r, h.domain, h.cookieKey)
	if err != nil {
		http.Error(w, err.Error(), 401)
		return
	}
	w.Write(id)
}

// handleLogin will redirect the user to Google's consent page to ask for
// permission for the scopes specified in h.Config.
//
// Use this when the user is not authenticated and the current GET request
// requires authorization. For POSTS you should just fail and expect the user
// to log on before posting.
func (h *oauthHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	_, err := getCookie(r, h.domain, h.cookieKey)
	if err == nil {
		// If cookie is present and good, redirect to home as
		// authentication is complete.
		http.Redirect(w, r, "/", 307)
		return
	}

	if err != http.ErrNoCookie {
		// If cookie is present but bad, delete it now.
		deleteCookie(w, h.domain)
	}

	// Now cookie is not present, procede with OAuth

	origin := r.URL.String()
	b, err := encryptBytes(h.stateKey, []byte(origin))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	url := h.AuthCodeURL(base64.URLEncoding.EncodeToString(b))
	http.Redirect(w, r, url, 307)
}

// handleRedirect gets the redirect from Google OAuth with the authorization
// codes, retrieves the scopes from the identity provider, issues a cookie, and
// redirects to the original URL.
func (h *oauthHandler) handleRedirect(w http.ResponseWriter, r *http.Request) {
	// TODO: differentiate user facing errors from debug errors
	rawState, err := base64.URLEncoding.DecodeString(r.FormValue("state"))
	if err != nil {
		http.Error(w, err.Error(), 401)
		return
	}
	b, err := decryptBytes(h.stateKey, rawState)
	if err != nil {
		http.Error(w, err.Error(), 401)
		return
	}
	home := string(b)

	tok, err := h.Exchange(context.Background(), r.FormValue("code"))
	if err != nil {
		http.Error(w, err.Error(), 401)
		return
	}

	v := tok.Extra("id_token")
	if v == nil {
		http.Error(w, "id_token not found in oauth", 401)
		return
	}

	// TODO: parse v to extract id
	id := "TODO"
	// TODO: store user profile details using id

	setCookie(w, h.domain, h.cookieKey, []byte(id))
	http.Redirect(w, r, home, 307)
}

var (
	errCookieExpired = errors.New("cookie expired")
	errCookieDomain  = errors.New("cookie used for wrong domain")
)

func getCookie(r *http.Request, domain string, key *[32]byte) ([]byte, error) {
	c, err := r.Cookie("session")
	if err != nil {
		return nil, err
	}
	in, err := base64.URLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil, err
	}
	b, err := decryptBytes(key, in)
	if err != nil {
		return nil, err
	}

	ts := binary.BigEndian.Uint64(b)
	if time.Since(time.Unix(int64(ts), 0)) > 24*time.Hour {
		return nil, errCookieExpired
	}
	b = b[8:]

	dcheck := []byte(domain)
	if !bytes.Equal(b[:len(dcheck)], dcheck) {
		return nil, errCookieDomain
	}
	b = b[len(dcheck):]

	return b, nil
}

func setCookie(w http.ResponseWriter, domain string, key *[32]byte, in []byte) {
	dcheck := []byte(domain)
	tb := make([]byte, len(in)+8+len(dcheck))

	// Ensure user doesn't mess with the time
	now := time.Now()
	binary.BigEndian.PutUint64(tb, uint64(now.Unix()))

	// Ensure user doesn't mess with the domain
	copy(tb[8:], dcheck)

	// Ensure user doesn't mess with the payload
	copy(tb[8+len(dcheck):], in)

	out, err := encryptBytes(key, tb)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    base64.URLEncoding.EncodeToString(out),
		Expires:  now.Add(24 * time.Hour),
		Path:     "/", // ALL PATHS
		Domain:   domain,
		Secure:   true, // DON'T SEND UNENCRYPTED
		HttpOnly: true, // NO CLIENT SIDE SHENANIGANS
	})
}

func deleteCookie(w http.ResponseWriter, domain string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Expires:  time.Unix(0, 0),
		Path:     "/",
		Domain:   domain,
		Secure:   true,
		HttpOnly: true,
	})
}

func newKey() (*[32]byte, error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return nil, err
	}
	return &k, nil
}

func encryptBytes(k *[32]byte, b []byte) ([]byte, error) {
	var nonce [24]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return nil, err
	}
	out := secretbox.Seal(nonce[:], b, &nonce, k)
	return out, nil
}

var errInvalidCipher = errors.New("Invalid Cipher: could not decrypt bytes provided")

func decryptBytes(key *[32]byte, b []byte) ([]byte, error) {
	if len(b) < 24 {
		return nil, errInvalidCipher
	}
	var nonce [24]byte
	copy(nonce[:], b)
	out, ok := secretbox.Open(nil, b[len(nonce):], &nonce, key)
	if !ok {
		return nil, errInvalidCipher
	}
	return out, nil
}
