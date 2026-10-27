package main

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
)

const sessionCookie = "session"

// SessionStore keeps logged-in sessions in memory. Restarting the app logs
// everyone out, which is fine for a local lab.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]int // token -> user ID
}

func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[string]int)}
}

func (s *SessionStore) Create(userID int) string {
	b := make([]byte, 16)
	rand.Read(b)
	token := hex.EncodeToString(b)

	s.mu.Lock()
	s.sessions[token] = userID
	s.mu.Unlock()
	return token
}

func (s *SessionStore) Get(token string) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.sessions[token]
	return id, ok
}

func (s *SessionStore) Delete(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// VULN-5 (insecure session cookie): the cookie has no HttpOnly, Secure or
// SameSite flags. Without HttpOnly, JavaScript on the page (for example from
// the XSS in VULN-2) can read document.cookie and steal the session.
// The app also sends no security headers at all (no Content-Security-Policy,
// X-Frame-Options, X-Content-Type-Options and so on).
func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:  sessionCookie,
		Value: token,
		Path:  "/",
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookie,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}

// currentUserID returns the logged-in user's ID, if there is one.
func (app *App) currentUserID(r *http.Request) (int, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return 0, false
	}
	return app.sessions.Get(c.Value)
}

// requireLogin sends logged-out visitors to the login page.
func (app *App) requireLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := app.currentUserID(r); !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}
