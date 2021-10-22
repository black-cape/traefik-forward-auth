package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/namsral/flag"
	"github.com/sirupsen/logrus"
)

// Vars
var fw *ForwardAuth
var log logrus.FieldLogger

// Add CORs related headers
func allowCors(w *http.ResponseWriter, allowedHeaders string) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	if allowedHeaders != "" {
		(*w).Header().Set("Access-Control-Allow-Headers", allowedHeaders)
	}
}

// Primary handler
func handler(w http.ResponseWriter, r *http.Request) {
	// Logging setup
	logger := log.WithFields(logrus.Fields{
		"SourceIP": r.Header.Get("X-Forwarded-For"),
	})
	logger.WithFields(logrus.Fields{
		"Method":  r.Method,
		"Headers": r.Header,
	}).Debugf("Handling request")

	allowCors(&w, fw.tokenHeader)

	// NOTE: This assumes the traffic is behind a Traefik instance which will
	//  reroute OPTION requests as GETS causing redirect issues on the frontend.
	//  Traefik will store the original method in the X-Forwarded-Method header.
	//  This isn't secure and we should probably figure out how to prevent Traefik from doing this.
	if r.Header.Get("X-Forwarded-Method") == "OPTIONS" {
		logger.Debugf("Allowing valid Traefik routed requests that is doing a preflight options request")
		w.Header().Set("X-Forwarded-User", "")
		w.WriteHeader(200)
		return
	}

	// Parse uri
	uri, err := url.Parse(r.Header.Get("X-Forwarded-Uri"))
	if err != nil {
		logger.Errorf("Error parsing X-Forwarded-Uri, %v", err)
		http.Error(w, "Service unavailable", 503)
		return
	}

	var forwardedUser = ""
	logger.WithFields(logrus.Fields{
		"field": fw.tokenHeader,
		"value": r.Header.Get(fw.tokenHeader),
	}).Debugf("Token information.")

	// Handle callback if no token header is set or found.
	if fw.tokenHeader == "" || r.Header.Get(fw.tokenHeader) == "" {
		if uri.Path == fw.Path {
			logger.Debugf("Passing request to auth callback")
			handleCallback(w, r, uri.Query(), logger)
			return
		}

		// Get auth cookie
		c, err := r.Cookie(fw.CookieName)
		if err != nil {
			logger.Debugf("Received error, %v", err)
			// Error indicates no cookie, generate nonce
			err, nonce := fw.Nonce()
			if err != nil {
				logger.Errorf("Error generating nonce, %v", err)
				http.Error(w, "Service unavailable", 503)
				return
			}

			// Set the CSRF cookie
			http.SetCookie(w, fw.MakeCSRFCookie(r, nonce))
			logger.Debug("Set CSRF cookie and redirecting to oidc login")
			logger.Debug("uri.Path was %s", uri.Path)
			logger.Debug("fw.Path was %s", fw.Path)

			// Forward them on
			http.Redirect(w, r, fw.GetLoginURL(r, nonce), http.StatusTemporaryRedirect)

			return
		}

		// Validate cookie
		valid, email, err := fw.ValidateCookie(r, c)
		if !valid {
			logger.Errorf("Invalid cookie: %v", err)
			http.Error(w, "Not authorized", 401)
			return
		}

		// Validate user
		valid = fw.ValidateEmail(email)
		if !valid {
			logger.WithFields(logrus.Fields{
				"email": email,
			}).Errorf("Invalid email")
			http.Error(w, "Not authorized", 401)
			return
		}

		forwardedUser = email
	} else {
		var token = r.Header.Get(fw.tokenHeader)
		var bearer = "Bearer " + token

		logger.Debugf("Found field with token. Will verify token.", token)
		req, err := http.NewRequest(http.MethodGet, fw.UserURL.String(), nil)
		req.Header.Add("Authorization", bearer)
		client := &http.Client{}
		// Make a call to the OIDC provider with the token to verify access
		resp, err := client.Do(req)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"token": token,
			}).Errorf("Invalid token provided")
			http.Error(w, "Not authorized", 401)
			return
		}

		body, _ := ioutil.ReadAll(resp.Body)
		logger.WithFields(logrus.Fields{
			"user": string(body),
		}).Info("Successfully verified user.")
		forwardedUser = token
	}

	// Valid request
	logger.Debugf("Allowing valid request ")
	w.Header().Set("X-Forwarded-User", forwardedUser)
	w.WriteHeader(200)
}

// Authenticate user after they have come back from oidc
func handleCallback(w http.ResponseWriter, r *http.Request, qs url.Values,
	logger logrus.FieldLogger) {
	// Check for CSRF cookie
	csrfCookie, err := r.Cookie(fw.CSRFCookieName)
	if err != nil {
		logger.Warn("Missing csrf cookie")
		http.Error(w, "Not authorized", 401)
		return
	}

	// Validate state
	state := qs.Get("state")
	valid, redirect, err := fw.ValidateCSRFCookie(csrfCookie, state)
	if !valid {
		logger.WithFields(logrus.Fields{
			"csrf":  csrfCookie.Value,
			"state": state,
		}).Warnf("Error validating csrf cookie: %v", err)
		http.Error(w, "Not authorized", 401)
		return
	}

	// Clear CSRF cookie
	http.SetCookie(w, fw.ClearCSRFCookie(r))

	// Exchange code for token
	token, err := fw.ExchangeCode(r, qs.Get("code"))
	if err != nil {
		logger.Errorf("Code exchange failed with: %v", err)
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Get user
	user, err := fw.GetUser(token)
	if err != nil {
		logger.Errorf("Error getting user: %s", err)
		return
	}

	// Generate cookie
	http.SetCookie(w, fw.MakeCookie(r, user.Email))
	logger.WithFields(logrus.Fields{
		"user": user.Email,
	}).Infof("Generated auth cookie")

	// Redirect
	http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
}

func getOidcConfig(oidc string) map[string]interface{} {
	uri, err := url.Parse(oidc)
	if err != nil {
		log.Fatal("failed to parse oidc string")
	}


	log.Info("in get OIDC config")
	log.Info(uri)

	uri.Path = path.Join(uri.Path, "/.well-known/openid-configuration")
	res, err := http.Get(uri.String())

	if err != nil {
		fmt.Println(err)
		log.Fatal("failed to get oidc parametere from oidc connect")
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal("failed to read response body")
	}
	var result map[string]interface{}
	json.Unmarshal(body, &result)
	log.Debug(result)
	return result
}

// Main
func main() {
	// Parse options
	flag.String(flag.DefaultConfigFlagname, "", "Path to config file")
	path := flag.String("url-path", "_oauth", "Callback URL")
	lifetime := flag.Int("lifetime", 43200, "Session length in seconds")
	secret := flag.String("secret", "", "*Secret used for signing (required)")
	authHost := flag.String("auth-host", "", "Central auth login")
	oidcIssuer := flag.String("oidc-issuer", "", "OIDC Issuer URL (required)")
	clientId := flag.String("client-id", "", "Client ID (required)")
	clientSecret := flag.String("client-secret", "", "Client Secret (required)")
	cookieName := flag.String("cookie-name", "_forward_auth", "Cookie Name")
	cSRFCookieName := flag.String("csrf-cookie-name", "_forward_auth_csrf", "CSRF Cookie Name")
	cookieDomainList := flag.String("cookie-domains", "", "Comma separated list of cookie domains") //todo
	cookieSecret := flag.String("cookie-secret", "", "Deprecated")
	cookieSecure := flag.Bool("cookie-secure", true, "Use secure cookies")
	domainList := flag.String("domain", "", "Comma separated list of email domains to allow")
	emailWhitelist := flag.String("whitelist", "", "Comma separated list of emails to allow")
	prompt := flag.String("prompt", "", "Space separated list of OpenID prompt options")
	logLevel := flag.String("log-level", "warn", "Log level: trace, debug, info, warn, error, fatal, panic")
	logFormat := flag.String("log-format", "text", "Log format: text, json, pretty")
	insecure := flag.Bool("insecure", false, "Disable verifying SSL certificates")
	tokenHeader := flag.String("token-header", "", "An optional header that holds a token as an alternative form of authentication.")
	flag.Parse()

	// Setup logger
	log = CreateLogger(*logLevel, *logFormat)

	// If insecure then skip verifying certs
	if *insecure {
		log.Info("Disabling SSL certificate verification.")
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// Backwards compatibility
	if *secret == "" && *cookieSecret != "" {
		*secret = *cookieSecret
	}

	// Check for show stopper errors
	if *clientId == "" || *clientSecret == "" || *secret == "" || *oidcIssuer == "" {
		log.Fatal("client-id, client-secret, secret and oidc-issuer must all be set")
	}

	var oidcParams = getOidcConfig(*oidcIssuer)

	loginUrl, err := url.Parse((oidcParams["authorization_endpoint"].(string)))
	if err != nil {
		log.Fatal("unable to parse login url")
	}

	tokenUrl, err := url.Parse((oidcParams["token_endpoint"].(string)))
	if err != nil {
		log.Fatal("unable to parse token url")
	}
	userUrl, err := url.Parse((oidcParams["userinfo_endpoint"].(string)))
	if err != nil {
		log.Fatal("unable to parse user url")
	}

	// Parse lists
	var cookieDomains []CookieDomain
	if *cookieDomainList != "" {
		for _, d := range strings.Split(*cookieDomainList, ",") {
			cookieDomain := NewCookieDomain(d)
			cookieDomains = append(cookieDomains, *cookieDomain)
		}
	}

	var domain []string
	if *domainList != "" {
		domain = strings.Split(*domainList, ",")
	}
	var whitelist []string
	if *emailWhitelist != "" {
		whitelist = strings.Split(*emailWhitelist, ",")
	}

	// Setup
	fw = &ForwardAuth{
		Path:     fmt.Sprintf("/%s", *path),
		Lifetime: time.Second * time.Duration(*lifetime),
		Secret:   []byte(*secret),
		AuthHost: *authHost,

		ClientId:     *clientId,
		ClientSecret: *clientSecret,
		Scope:        "openid profile email",

		LoginURL: loginUrl,
		TokenURL: tokenUrl,
		UserURL:  userUrl,

		CookieName:     *cookieName,
		CSRFCookieName: *cSRFCookieName,
		CookieDomains:  cookieDomains,
		CookieSecure:   *cookieSecure,

		Domain:    domain,
		Whitelist: whitelist,

		Prompt: *prompt,

		tokenHeader: *tokenHeader,
	}

	// Attach handler
	http.HandleFunc("/", handler)

	// Start
	jsonConf, _ := json.Marshal(fw)
	log.Debugf("Starting with options: %s", string(jsonConf))
	log.Info("Listening on :4181")
	log.Info(http.ListenAndServe(":4181", nil))
}
