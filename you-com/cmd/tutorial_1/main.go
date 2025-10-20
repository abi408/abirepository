package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	users           = [2]string{"abi", "abraham"}
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
	if username == "" || password != "secret" {
		return "", &APIError{ErrorCode: 401, ErrorStr: "Invalid username or password"}
	}
	found := false
	for _, value := range users {
		if value == username {
			found = true
		}
	}
	if !found {
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

	// GET /chats
	//		Return chats associated with a user
	//		pagination: offset, limit
	//		filter: By Chat title
	case http.MethodGet:
		offsetStr := r.URL.Query().Get("offset")
		limitStr := r.URL.Query().Get("limit")
		titleFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("title")))

		offset, _ := strconv.Atoi(offsetStr)
		limit, _ := strconv.Atoi(limitStr)
		if limit <= 0 {
			limit = 10
		}
		storeMu.Lock()
		defer storeMu.Unlock()
		userChats := chatStore[username]
		filtered := make([]Chat, 0, len(userChats))
		for _, c := range userChats {
			if titleFilter == "" || strings.Contains(strings.ToLower(c.ChatTitle), titleFilter) {
				filtered = append(filtered, c)
			}
		}
		end := offset + limit
		if offset > len(filtered) {
			offset = len(filtered)
		}
		if end > len(filtered) {
			end = len(filtered)
		}
		result := filtered[offset:end]
		json.NewEncoder(w).Encode(result)

	// POST /chats
	//		Create a new Chat.
	//		Chat is created based on Chat Title
	//		When a chat is created a UUID is created for the chat
	//		A chat has a history of question, answer pair
	//		Return Chat information which contains chat uuid
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
		tag := generateUUID()
		chatS := Chat{UserId: username, ChatTitle: req.ChatTitle, ChatId: chatUuid, QuestionAnswers: nil, Tag: tag}
		chats[chatUuid] = chatS
		chatStore[username] = chats
		chatTitleToChat = chats
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
		fmt.Println(status)
		var code int
		fmt.Sscanf(status, "%d", &code)
		w.WriteHeader(code)
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
	// POST /chats/{chatUuid}/answer
	//		Allows getting an answer for a question
	//			All the question and answers in this chat (with {chatUuid} is
	//			used a context)
	//		Return the answer for a question asked in context of chat with
	// 			id {chatUuid}
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
	// GET /chats/{chatUuid}
	//		Return chat with id {chatUuid}
	case http.MethodGet:
		json.NewEncoder(w).Encode(chatS)
	// PATCH /chats/{chatUuid}
	//		Allows changing the title of a Chat
	//		Ensure that the chat is changed only of tag matches. This is done
	//			to take care of concurrent read-modify-write operation.
	//		Return the changed chat with id {chatUuid}
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
		ot := chatS.ChatTitle
		chatS.ChatTitle = req.ChatTitle
		chatStore[username][chatUuid] = chatS
		delete(chatTitleToChat, ot)
		chatS.Tag = generateUUID()
		chatTitleToChat[req.ChatTitle] = chatS
		json.NewEncoder(w).Encode(chatS)
	// DELETE /chats/{chatUuid}
	//		Allows deleting a chat
	//		Return no content
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
		fmt.Println(chatStore)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func fetchAnswer(w http.ResponseWriter, username string, chatUuid string, question string) (string, string) {
	url := "https://chat-api.you.com/smart"
	apiKey := "e7e0734b-98e5-468e-ba0e-0ac800088746<__>1QwX5qETU8N2v5f4zKakO3rt"

	storeMu.Lock()
	chats, exists := chatStore[username][chatUuid]
	storeMu.Unlock()
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

	storeMu.Lock()
	chats = chatStore[username][chatUuid]
	a := QuestionAnswer{Question: question, Answer: string(body)}
	chats.QuestionAnswers = append(chats.QuestionAnswers, a)
	chatStore[username][chatUuid] = chats
	storeMu.Unlock()
	return resp.Status, string(body)
}

func main() {
	http.HandleFunc("/chats", chatsHandler)
	http.HandleFunc("/chats/", chatByIDHandler)
	log.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
