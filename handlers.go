package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)
// pageData is what every template receives.
type pageData struct {
	User  *User
	Error string
	Data  any
}

func (app *App) render(w http.ResponseWriter, r *http.Request, page string, data any, errMsg string) {
	pd := pageData{Error: errMsg, Data: data}
	if id, ok := app.currentUserID(r); ok {
		pd.User, _ = app.getUser(id)
	}
	if err := app.templates[page].ExecuteTemplate(w, "layout", pd); err != nil {
		log.Printf("render %s: %v", page, err)
	}
}

func (app *App) getUser(id int) (*User, error) {
	u := &User{}
	err := app.db.QueryRow(
		"SELECT id, username, full_name, email, org, bio FROM users WHERE id = ?", id,
	).Scan(&u.ID, &u.Username, &u.FullName, &u.Email, &u.Org, &u.Bio)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (app *App) home(w http.ResponseWriter, r *http.Request) {
	if _, ok := app.currentUserID(r); ok {
		http.Redirect(w, r, "/proposals", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- Login, register, logout ----

func (app *App) loginPage(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "login", nil, "")
}

func (app *App) login(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// VULN-1 (SQL injection): the username is pasted straight into the SQL
	// string. Typing  amara' --  as the username comments out the password
	// check and logs you in as amara without knowing her password.
	

	var id int
	var storedHash string
	err := app.db.QueryRow(
		"SELECT id, password_hash FROM users WHERE username = ?",
		username,
	).Scan(&id, &storedHash)
	if err == nil {
		err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
	}
	if err != nil {
		app.render(w, r, "login", nil, "Wrong username or password.")
		return
	}

	setSessionCookie(w, app.sessions.Create(id))
	http.Redirect(w, r, "/proposals", http.StatusSeeOther)
}

func (app *App) registerPage(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "register", nil, "")
}

func (app *App) register(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	fullName := strings.TrimSpace(r.FormValue("full_name"))

	if username == "" || password == "" {
		app.render(w, r, "register", nil, "Username and password are required.")
		return
	}

	res, err := app.db.Exec(
		"INSERT INTO users (username, password_hash, full_name) VALUES (?, ?, ?)",
		username, hashPassword(password), fullName,
	)
	if err != nil {
		app.render(w, r, "register", nil, "That username is taken.")
		return
	}
	id, _ := res.LastInsertId()

	setSessionCookie(w, app.sessions.Create(int(id)))
	http.Redirect(w, r, "/proposals", http.StatusSeeOther)
}

func (app *App) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		app.sessions.Delete(c.Value)
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- Profile ----

func (app *App) profilePage(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "profile", nil, "")
}

func (app *App) updateProfile(w http.ResponseWriter, r *http.Request) {
	id, _ := app.currentUserID(r)
	_, err := app.db.Exec(
		"UPDATE users SET full_name = ?, email = ?, org = ?, bio = ? WHERE id = ?",
		r.FormValue("full_name"), r.FormValue("email"), r.FormValue("org"), r.FormValue("bio"), id,
	)
	if err != nil {
		app.render(w, r, "profile", nil, "Could not save your profile.")
		return
	}
	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

// ---- Proposals ----

func (app *App) listProposals(w http.ResponseWriter, r *http.Request) {
	id, _ := app.currentUserID(r)
	rows, err := app.db.Query(
		"SELECT id, title, track, status, created_at FROM proposals WHERE user_id = ? ORDER BY id DESC", id,
	)
	if err != nil {
		http.Error(w, "could not load proposals", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var list []Proposal
	for rows.Next() {
		var p Proposal
		if err := rows.Scan(&p.ID, &p.Title, &p.Track, &p.Status, &p.CreatedAt); err == nil {
			list = append(list, p)
		}
	}
	app.render(w, r, "proposals", list, "")
}

func (app *App) newProposalPage(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "new_proposal", nil, "")
}

func (app *App) createProposal(w http.ResponseWriter, r *http.Request) {
	id, _ := app.currentUserID(r)
	title := strings.TrimSpace(r.FormValue("title"))
	abstract := r.FormValue("abstract")
	track := r.FormValue("track")
	status := "draft"
	if r.FormValue("submit") == "yes" {
		status = "submitted"
	}

	if title == "" || abstract == "" {
		app.render(w, r, "new_proposal", nil, "Title and abstract are required.")
		return
	}

	res, err := app.db.Exec(
		"INSERT INTO proposals (user_id, title, abstract, track, status) VALUES (?, ?, ?, ?, ?)",
		id, title, abstract, track, status,
	)
	if err != nil {
		app.render(w, r, "new_proposal", nil, "Could not save your proposal.")
		return
	}
	newID, _ := res.LastInsertId()
	http.Redirect(w, r, fmt.Sprintf("/proposals/%d", newID), http.StatusSeeOther)
}

// proposalView is the proposal page's data. AbstractHTML is the abstract
// marked as "safe" HTML.
type proposalView struct {
	Proposal
	AbstractHTML template.HTML
}

func (app *App) showProposal(w http.ResponseWriter, r *http.Request) {
	propID, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// VULN-3 (IDOR / broken access control): the query looks the proposal up
	// by ID only. It never checks that it belongs to the logged-in speaker, so
	// changing /proposals/3 to /proposals/2 shows someone else's unpublished draft.
	userID, _ := app.currentUserID(r)
	var p Proposal
	err = app.db.QueryRow(`
		SELECT p.id, p.user_id, u.full_name, p.title, p.abstract, p.track, p.status, p.created_at
		FROM proposals p JOIN users u ON u.id = p.user_id
		WHERE p.id = ? AND p.user_id = ?`, propID, userID,
	).Scan(&p.ID, &p.UserID, &p.Speaker, &p.Title, &p.Abstract, &p.Track, &p.Status, &p.CreatedAt)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// VULN-2 (stored XSS): converting the abstract to template.HTML tells Go
	// "trust this, don't escape it". Any <script> a speaker writes in their
	// abstract runs in the browser of everyone who opens the proposal.
	view := proposalView{Proposal: p}
	app.render(w, r, "proposal", view, "")
}
