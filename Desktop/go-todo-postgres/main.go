package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	tmpl    = template.Must(template.ParseGlob("templates/*.html"))
	store   = sessions.NewCookieStore([]byte("super-secret-key"))
	db      *sql.DB
	connStr = "user=postgres password=password dbname=todoapp sslmode=disable"
)

func init() {

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	err = db.Ping()
	if err != nil {
		log.Fatal("Unable to connect to database:", err)
	}
}

// User structure
type User struct {
	ID       int
	Username string
	Password string
}

// Task structure
type Task struct {
	ID     int
	Name   string
	Done   bool
	UserID int
}

// Home page (Login page or Task List if authenticated)
func homeHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	userID := session.Values["user_id"]

	if userID == nil {
		http.Redirect(w, r, "/index", http.StatusFound)
		return
	}

	rows, err := db.Query("SELECT id, name, done FROM tasks WHERE user_id = $1", userID)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	tasks := []Task{}
	for rows.Next() {
		var task Task
		if err := rows.Scan(&task.ID, &task.Name, &task.Done); err != nil {
			log.Fatal(err)
		}
		tasks = append(tasks, task)
	}

	tmpl.ExecuteTemplate(w, "tasks.html", tasks)
}

// Signup Handler
func signupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Hash password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Fatal(err)
		}

		_, err = db.Exec("INSERT INTO users (username, password) VALUES ($1, $2)", username, hashedPassword)
		if err != nil {
			log.Fatal(err)
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	tmpl.ExecuteTemplate(w, "signup.html", nil)
}

// Login Handler
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		user := User{}
		err := db.QueryRow("SELECT id, password FROM users WHERE username = $1", username).Scan(&user.ID, &user.Password)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Compare passwords
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Create session
		session, _ := store.Get(r, "session")
		session.Values["user_id"] = user.ID
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	tmpl.ExecuteTemplate(w, "login.html", nil)
}

// Add task handler
func addTaskHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	userID := session.Values["user_id"]
	if userID == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.Method == http.MethodPost {
		task := r.FormValue("task")
		_, err := db.Exec("INSERT INTO tasks (name, user_id) VALUES ($1, $2)", task, userID)
		if err != nil {
			log.Fatal(err)
		}

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

// Delete task handler
func deleteTaskHandler(w http.ResponseWriter, r *http.Request) {
	taskID, _ := strconv.Atoi(mux.Vars(r)["id"])
	_, err := db.Exec("DELETE FROM tasks WHERE id = $1", taskID)
	if err != nil {
		log.Fatal(err)
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// Mark task as done
func doneTaskHandler(w http.ResponseWriter, r *http.Request) {
	taskID, _ := strconv.Atoi(mux.Vars(r)["id"])
	_, err := db.Exec("UPDATE tasks SET done = true WHERE id = $1", taskID)
	if err != nil {
		log.Fatal(err)
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/login", loginHandler)
	r.HandleFunc("/signup", signupHandler)
	r.HandleFunc("/add", addTaskHandler)
	r.HandleFunc("/delete/{id}", deleteTaskHandler)
	r.HandleFunc("/done/{id}", doneTaskHandler)

	http.Handle("/", r)

	fmt.Println("Server started at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
