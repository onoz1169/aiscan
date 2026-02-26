// Intentionally vulnerable web server for aiscan testing.
// DO NOT use in production. Every misconfiguration is deliberate.
package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux()

	// addBadHeaders adds intentionally missing/misconfigured headers to a response.
	addBadHeaders := func(w http.ResponseWriter, r *http.Request) {
		// CORS: reflect arbitrary origin with credentials (WEB-020: CRITICAL)
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		// No HSTS, No CSP, No X-Frame-Options, No X-Content-Type-Options, No Referrer-Policy
		w.Header().Set("Server", "Apache/2.4.51 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
	}

	// Root: intentional misconfigurations, exact path only
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		addBadHeaders(w, r)
		// Insecure cookies (WEB-015/016/017)
		http.SetCookie(w, &http.Cookie{
			Name:  "session",
			Value: "abc123",
			// No Secure, no HttpOnly, no SameSite
		})
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body><h1>Test App</h1></body></html>")
	})

	// TRACE method enabled (WEB-019: MEDIUM)
	mux.HandleFunc("/trace-test", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodTrace {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "TRACE OK")
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	// Stack trace in response (WEB-018: HIGH)
	mux.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, `Traceback (most recent call last):
  File "/app/views.py", line 42, in get_user
    user = User.objects.get(id=user_id)
  File "/usr/local/lib/python3.9/site-packages/django/db/models/manager.py", line 82
    DoesNotExist: User matching query does not exist.`)
	})

	// .env file exposed (WEB-028: CRITICAL)
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, `APP_NAME=TestApp
APP_KEY=base64:abc123secret
DB_HOST=127.0.0.1
DB_PASSWORD=supersecret123
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_abc123def456`)
	})

	// .git/HEAD exposed (WEB-028: HIGH)
	mux.HandleFunc("/.git/HEAD", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ref: refs/heads/main\n")
	})

	// phpinfo exposed (WEB-028: HIGH)
	mux.HandleFunc("/phpinfo.php", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body><h1>PHP Version 7.4.3</h1><p>phpinfo output here</p></body></html>")
	})

	// Swagger exposed (WEB-028: MEDIUM)
	mux.HandleFunc("/swagger.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"swagger":"2.0","info":{"title":"Test API","version":"1.0.0"},"paths":{}}`)
	})

	// Directory listing (WEB-030: HIGH)
	mux.HandleFunc("/files/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Index of /files/</title></head><body>
<h1>Index of /files/</h1>
<pre><a href="../">Parent Directory</a>
<a href="backup.sql">backup.sql</a>
<a href="users.csv">users.csv</a>
</pre></body></html>`)
	})

	// Override default handler to support TRACE on root (aiscan sends TRACE to /)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "TRACE" {
			w.Header().Set("Server", "Apache/2.4.51 (Ubuntu)")
			w.WriteHeader(http.StatusOK)
			return
		}
		mux.ServeHTTP(w, r)
	})

	log.Println("Vulnerable web server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}
