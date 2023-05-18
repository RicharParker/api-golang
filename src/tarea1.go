package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

const (
	dbHost     = "localhost"
	dbPort     = "5432"
	dbName     = "db_test"
	dbUser     = "administrador"
	dbPassword = "123"
	jwtSecret  = "myjwtsecret"
)

var db *sql.DB

func main() {
	var err error
	db, err = sql.Open("postgres", fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s sslmode=disable", dbHost, dbPort, dbName, dbUser, dbPassword))
	if err != nil {
		log.Fatal(err)
	}

	err = createDefaultAdmin()
	if err != nil {
		log.Fatal(err)
	}

	router := mux.NewRouter()

	router.HandleFunc("/", mesajeIncio).Methods("GET")
	router.HandleFunc("/register", registerHandler).Methods("POST")
	router.HandleFunc("/login", loginHandler).Methods("POST")
	router.Handle("/users", authMiddleware(http.HandlerFunc(usersHandler))).Methods("GET")
	router.Handle("/users", authMiddleware(http.HandlerFunc(createUserHandler))).Methods("POST")
	router.Handle("/users/{id}", authMiddleware(http.HandlerFunc(updateUserHandler))).Methods("PUT")
	router.Handle("/users/{id}", authMiddleware(http.HandlerFunc(deleteUserHandler))).Methods("DELETE")
	router.Handle("/users/{id}", authMiddleware(http.HandlerFunc(getUserHandler))).Methods("GET")

	fmt.Println("Server listening on port 8000")

	http.ListenAndServe(":8000", router)
}

func mesajeIncio(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Bienvenido al servidor")
}
func createDefaultAdmin() error {
	email := "admin@example.com"
	password := "123"

	// Check if admin account already exists
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE email = $1", email).Scan(&count)
	if err != nil {
		return err
	}

	// If admin account already exists, return without creating a new one
	if count > 0 {
		return nil
	}

	// Admin account doesn't exist, proceed with creation
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = db.Exec("INSERT INTO users (email, password) VALUES ($1, $2)", email, string(hash))
	if err != nil {
		return err
	}

	return nil
}

type registrationRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var req registrationRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO users (email, password) VALUES ($1, $2)", req.Email, string(hash))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token string `json:"token"`
}
type User struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var id int
	var hashedPassword string
	err = db.QueryRow("SELECT id, password FROM users WHERE email = $1", req.Email).Scan(&id, &hashedPassword)
	if err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password)); err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": id,
	})

	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := loginResponse{
		Token: tokenString,
	}

	json.NewEncoder(w).Encode(response)
}

type userIDKey string

const (
	UserIDKey userIDKey = "userID"
)

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "No estas autorizado", http.StatusUnauthorized)
			return
		}

		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Verificar el método de firma
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(jwtSecret), nil
		})
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			userID := claims["sub"].(float64)
			// Convertir el ID de usuario a tipo int
			userIDInt := int(userID)
			// Agregar el ID de usuario al contexto de la solicitud
			ctx := context.WithValue(r.Context(), UserIDKey, userIDInt)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		http.Error(w, "Invalid token", http.StatusUnauthorized)
	})
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
	// Consultar la base de datos para obtener todos los usuarios con su correo, contraseña e ID
	rows, err := db.Query("SELECT id, email, password FROM users")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Crear una estructura para almacenar la lista de usuarios
	type User struct {
		ID       int    `json:"id"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var users []User

	// Recorrer cada fila y agregar el usuario a la lista
	for rows.Next() {
		var id int
		var email, password string
		err := rows.Scan(&id, &email, &password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		user := User{
			ID:       id,
			Email:    email,
			Password: password,
		}
		users = append(users, user)
	}
	if err = rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Establecer el encabezado Content-Type y codificar la lista de usuarios como JSON
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(users)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func createUserHandler(w http.ResponseWriter, r *http.Request) {
	// Decodificar los datos del nuevo usuario desde el cuerpo de la solicitud
	var newUser struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Verificar si el usuario ya existe en la base de datos
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users WHERE email = $1", newUser.Email).Scan(&count)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if count > 0 {
		http.Error(w, "El usuario ya existe", http.StatusConflict)
		return
	}

	// Generar el hash de la contraseña del nuevo usuario
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Insertar el nuevo usuario en la base de datos
	_, err = db.Exec("INSERT INTO users (email, password) VALUES ($1, $2)", newUser.Email, string(hashedPassword))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Usuario creado exitosamente")
}

func updateUserHandler(w http.ResponseWriter, r *http.Request) {
	// Obtener el ID del usuario de los parámetros de la ruta
	vars := mux.Vars(r)
	userID := vars["id"]

	// Decodificar los datos del usuario del cuerpo de la solicitud
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Verificar si el usuario existe en la base de datos
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users WHERE id = $1", userID).Scan(&count)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if count == 0 {
		http.Error(w, "El usuario no existe", http.StatusNotFound)
		return
	}

	// Generar el hash bcrypt para la nueva contraseña
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Actualizar los datos del usuario en la base de datos
	_, err = db.Exec("UPDATE users SET email = $1, password = $2 WHERE id = $3", user.Email, string(hash), userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Devolver una respuesta exitosa
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Usuario Actualizado")
}

func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	// Obtener el ID del usuario de los parámetros de la ruta
	vars := mux.Vars(r)
	userID := vars["id"]

	// Ejecutar la consulta para eliminar el usuario
	_, err := db.Exec("DELETE FROM users WHERE id = $1", userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Devolver una respuesta exitosa
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Usuario eliminado")
}

// Controlador para obtener un usuario por ID
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	// Obtener el ID del usuario de los parámetros de la ruta
	vars := mux.Vars(r)
	userID := vars["id"]

	// Consultar la base de datos para obtener el usuario por su ID
	var email, password string
	err := db.QueryRow("SELECT email, password FROM users WHERE id = $1", userID).Scan(&email, &password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Crear una estructura para almacenar los datos del usuario

	user := User{
		ID:       userID,
		Email:    email,
		Password: password,
	}

	// Devolver el usuario como respuesta JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}
