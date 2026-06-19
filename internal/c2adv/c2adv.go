package c2adv

import "net/http"

type Engine struct{}

func New() *Engine {
	return &Engine{}
}

func RegisterHandlers(mux *http.ServeMux, engine *Engine) {}
