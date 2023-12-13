package handler

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/fantasticmao/nginx-log-analyzer/parser"
)

type PvAndUvHandler struct {
	pv      int32
	uv      int32
	uniqMap map[string]bool
	mu      sync.Mutex // Mutex to synchronize map access
}

func NewPvAndUvHandler() *PvAndUvHandler {
	return &PvAndUvHandler{
		pv:      0,
		uv:      0,
		uniqMap: make(map[string]bool),
	}
}

func (handler *PvAndUvHandler) Input(info *parser.LogInfo) {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	atomic.AddInt32(&handler.pv, 1)
	if _, ok := handler.uniqMap[info.RemoteAddr]; !ok {
		atomic.AddInt32(&handler.uv, 1)
		handler.uniqMap[info.RemoteAddr] = true
	}
}

func (handler *PvAndUvHandler) Output(limit int) {
	fmt.Printf("PV: %v\n", atomic.LoadInt32(&handler.pv))
	fmt.Printf("UV: %v\n", atomic.LoadInt32(&handler.uv))
}
