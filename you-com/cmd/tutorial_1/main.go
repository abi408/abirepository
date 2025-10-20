package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"
)

type Chat struct {
	UserId          string           `json:"userId"`
	ChatId          string           `json:"chatId"`
	ChatTitle       string           `json:"chatTitle"`
	QuestionAnswers []QuestionAnswer `json:"questionAnswers"`
	Tag             string           `json:"tag"`
}

type QuestionAnswer struct {
	Question string `json:"question"`
	Answer   string `json:"answer"`
}

type NewChatRequest struct {
	UserId    string `json:"userId"`
	ChatTitle string `json:"chatTitle"`
}

type AnswerRequest struct {
	Question string `json:"question"`
}

type AnswerResponse struct {
	Answer string `json:"answer"`
}

type ChatsRequest struct {
	UserId    string `json:"userId"`
	ChatTitle string `json:"chatTitle"`
}
type ErrorResponse struct {
	Errors []APIError `json:"errors"`
}
type APIError struct {
	ErrorCode int    `json:"errorCode"`
	ErrorStr  string `json:"errorStr"`
}

type ChatbotRequest struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Top-level: username → chatid → Chat
var (
	chatStore       = make(map[string]map[string]Chat)
	chatTitleToChat = make(map[string]Chat)
	storeMu         sync.Mutex
)

func basicAuth(r *http.Request) (string, *APIError) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		return "", &APIError{ErrorCode: 401, ErrorStr: "Missing or invalid Authorization header"}
	}
	payload, err := base64.StdEncoding.DecodeString(auth[len("Basic "):])
	if err != nil {
		return "", &APIError{ErrorCode: 401, ErrorStr: "Malformed base64 in Authorization header"}
	}
	parts := strings.SplitN(string(payload), ":", 2)
	if len(parts) != 2 {
		return "", &APIError{ErrorCode: 401, ErrorStr: "Malformed Authorization payload"}
	}
	username, password := parts[0], parts[1]
	// Demo fixed credentials
	if username == "" || password != "secret" {
		return "", &APIError{ErrorCode: 401, ErrorStr: "Invalid username or password"}
	}
	return username, nil
}

func generateUUID() string {
	return uuid.New().String()
}

func chatsHandler(w http.ResponseWriter, r *http.Request) {
	username, authErr := basicAuth(r)
	if authErr != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Errors: []APIError{*authErr}})
		return
	}

	switch r.Method {
	case http.MethodGet:
		storeMu.Lock()
		defer storeMu.Unlock()
		userChats := chatStore[username]
		chats := make([]Chat, 0, len(userChats))
		for _, c := range userChats {
			chats = append(chats, c)
		}
		json.NewEncoder(w).Encode(chats)

	case http.MethodPost:
		body, _ := ioutil.ReadAll(r.Body)
		var req NewChatRequest
		if err := json.Unmarshal(body, &req); err != nil || req.UserId == "" || req.ChatTitle == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Errors: []APIError{{ErrorCode: 400, ErrorStr: "Missing or invalid message"}},
			})
			return
		}
		storeMu.Lock()
		defer storeMu.Unlock()
		_, e := chatTitleToChat[req.ChatTitle]
		if e {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Errors: []APIError{{ErrorCode: 400, ErrorStr: "Chat Title already exists. Invalid Chat Title"}},
			})
			return
		}
		chats, exists := chatStore[username]
		if !exists {
			chats = make(map[string]Chat)
		}
		chatUuid := generateUUID()
		chatS := Chat{UserId: username, ChatTitle: req.ChatTitle, ChatId: chatUuid, QuestionAnswers: nil}
		chats[chatUuid] = chatS
		chatStore[username] = chats
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(chatS)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func chatAnswerHandler(username string, w http.ResponseWriter, r *http.Request) {
	// /chats/{chatId}/answer
	path := strings.TrimPrefix(r.URL.Path, "/chats/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "answer" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	chatUuid := parts[0]
	storeMu.Lock()
	userChats := chatStore[username]
	_, exists := userChats[chatUuid]
	storeMu.Unlock()
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{
			Errors: []APIError{{ErrorCode: 404, ErrorStr: "Chat not found"}},
		})
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req AnswerRequest
	body, _ := ioutil.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil || req.Question == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Errors: []APIError{{ErrorCode: 400, ErrorStr: "Missing or invalid question or answer"}},
		})
		return
	}

	status, ans := fetchAnswer(w, username, chatUuid, req.Question)

	if status != "200" {
		s, _ := strconv.Atoi(status)
		w.WriteHeader(s)
		json.NewEncoder(w).Encode(ErrorResponse{
			Errors: []APIError{{ErrorCode: 400, ErrorStr: ans}},
		})
		return
	}
	a := AnswerResponse{Answer: ans}
	json.NewEncoder(w).Encode(a)
}

func chatByIDHandler(w http.ResponseWriter, r *http.Request) {
	username, authErr := basicAuth(r)
	if authErr != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Errors: []APIError{*authErr}})
		return
	}
	chatUuid := strings.TrimPrefix(r.URL.Path, "/chats/")

	if strings.HasSuffix(r.URL.Path, "/answer") {
		chatAnswerHandler(username, w, r)
		return
	}

	storeMu.Lock()
	defer storeMu.Unlock()
	chatS, exists := chatStore[username][chatUuid]
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{
			Errors: []APIError{{ErrorCode: 404, ErrorStr: "Chat not found"}},
		})
		return
	}
	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(chatS)
	case http.MethodPatch:
		var req ChatsRequest
		body, _ := ioutil.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil || req.ChatTitle == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Errors: []APIError{{ErrorCode: 400, ErrorStr: "Missing or invalid Chat Title"}},
			})
			return
		}
		tag := r.Header.Get("tag")
		if chatS.Tag != tag {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Errors: []APIError{{ErrorCode: 400, ErrorStr: "Tag Mismatch"}},
			})
			return
		}
		chatS.ChatTitle = req.ChatTitle
		chatStore[username][chatUuid] = chatS
		json.NewEncoder(w).Encode(chatS)
	case http.MethodDelete:
		tag := r.Header.Get("tag")
		if chatS.Tag != tag {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Errors: []APIError{{ErrorCode: 400, ErrorStr: "Tag Mismatch"}},
			})
			return
		}
		delete(chatStore[username], chatUuid)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func fetchAnswer(w http.ResponseWriter, username string, chatUuid string, question string) (string, string) {
	url := "https://chat-api.you.com/smart"
	apiKey := "e7e0734b-98e5-468e-ba0e-0ac800088746<__>1QwX5qETU8N2v5f4zKakO3rt"

	defer storeMu.Unlock()
	chats, exists := chatStore[username][chatUuid]

	if !exists {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Errors: []APIError{{ErrorCode: 400, ErrorStr: "Bad ChatId"}},
		})
		return "", ""
	}

	var reqs []ChatbotRequest
	for _, qa := range chats.QuestionAnswers {
		qa := ChatbotRequest{
			Role:    "user",
			Content: qa.Question,
		}
		reqs = append(reqs, qa)
		qa = ChatbotRequest{
			Role:    "asistant",
			Content: qa.Content,
		}
		reqs = append(reqs, qa)
	}
	qa := ChatbotRequest{
		Role:    "user",
		Content: question,
	}
	reqs = append(reqs, qa)
	jsonBody, _ := json.Marshal(reqs)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		panic(err)
	}
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return resp.Status, string(body)
}

func main() {
	http.HandleFunc("/chats", chatsHandler)
	http.HandleFunc("/chats/", chatByIDHandler)
	log.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
