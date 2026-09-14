package plugin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// Sandbox limits applied to every plugin VM. These are deliberately tight —
// plugins are NOT a security boundary against a determined attacker (Lua
// can still allocate, churn the GC, or smuggle data through globals); they
// exist to bound the blast radius of an honest-but-buggy plugin and to
// prevent the most obvious abuse vectors (require'ing the filesystem,
// looping forever in C-speed math).
//
// Tuning: override at build time with -ldflags or per-deployment via env if
// you ship trusted plugins that need more headroom.
const (
	pluginMaxMemoryMB     = 64
	pluginInvocationLimit = 30 * time.Second
	pluginCallStackSize   = 256
	pluginRegistrySize    = 1024 * 64
)

// dangerousGlobals are the Lua names we wipe after opening the standard
// libs we DO allow. Some are added by base lib (load/loadstring), some are
// names a plugin author might expect to find and we want to fail loud
// instead of letting them try (io/os/debug).
var dangerousGlobals = []string{
	"require", "package", "module",
	"dofile", "loadfile", "load", "loadstring",
	"io", "os", "debug",
}

// Plugin represents a single loaded Lua plugin
type Plugin struct {
	name   string
	path   string
	LState *lua.LState
	mu     sync.Mutex
}

// Info returns metadata about the plugin
func (p *Plugin) Info() PluginInfo {
	return PluginInfo{
		Name: p.name,
		Path: p.path,
	}
}

func (p *Plugin) Run(ctx context.Context, target string, responseBody string, responseHeaders map[string]string) ([]Finding, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Per-invocation deadline. SetContext lets gopher-lua abort a Protect:true
	// call when ctx is cancelled, so a runaway plugin can't deadlock the scan.
	runCtx, cancel := context.WithTimeout(ctx, pluginInvocationLimit)
	defer cancel()
	p.LState.SetContext(runCtx)
	defer p.LState.RemoveContext()

	scanFn, err := p.getFunction("scan")
	if err != nil {
		return nil, err
	}

	if err := p.LState.CallByParam(lua.P{
		Fn:      scanFn,
		NRet:    1,
		Protect: true,
	}, lua.LString(target), lua.LString(responseBody), toLuaTable(p.LState, responseHeaders)); err != nil {
		return nil, fmt.Errorf("plugin %s scan() error: %w", p.name, err)
	}

	result := p.LState.Get(-1)
	p.LState.Pop(1)

	return parseFindings(p.LState, result), nil
}

// Close releases the Lua state
func (p *Plugin) Close() {
	if p.LState != nil {
		p.LState.Close()
	}
}

func (p *Plugin) getFunction(name string) (lua.LValue, error) {
	val := p.LState.GetGlobal(name)
	if fn, ok := val.(*lua.LFunction); ok {
		return fn, nil
	}
	return nil, fmt.Errorf("function %s not found", name)
}

// PluginEngine manages loading and running Lua plugins
type PluginEngine struct {
	plugins []PluginRunner
	mu      sync.RWMutex
}

// NewPluginEngine creates a new plugin engine
func NewPluginEngine() *PluginEngine {
	return &PluginEngine{
		plugins: make([]PluginRunner, 0),
	}
}

// Load loads all .lua plugins from the given directory.
// Returns without error if the directory does not exist (optional system).
func (e *PluginEngine) Load(dir string) error {
	if dir == "" {
		return nil
	}

	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("plugin directory error: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("plugin path is not a directory: %s", dir)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading plugin directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".lua") {
			continue
		}

		pluginPath := filepath.Join(dir, entry.Name())
		p, err := loadPlugin(pluginPath)
		if err != nil {
			return fmt.Errorf("loading plugin %s: %w", entry.Name(), err)
		}

		e.mu.Lock()
		e.plugins = append(e.plugins, p)
		e.mu.Unlock()
	}

	return nil
}

// RunAll executes all loaded plugins and collects findings
func (e *PluginEngine) RunAll(ctx context.Context, target string, responseBody string, responseHeaders map[string]string) []Finding {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if len(e.plugins) == 0 {
		return nil
	}

	var allFindings []Finding
	for _, p := range e.plugins {
		findings, err := p.Run(ctx, target, responseBody, responseHeaders)
		if err != nil {
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings
}

// Plugins returns info about loaded plugins
func (e *PluginEngine) Plugins() []PluginInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()

	infos := make([]PluginInfo, len(e.plugins))
	for i, p := range e.plugins {
		infos[i] = p.Info()
	}
	return infos
}

// Count returns the number of loaded plugins
func (e *PluginEngine) Count() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.plugins)
}

// Close releases all plugin resources
func (e *PluginEngine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, p := range e.plugins {
		p.Close()
	}
	e.plugins = nil
}

func loadPlugin(path string) (*Plugin, error) {
	L := lua.NewState(lua.Options{
		SkipOpenLibs:        true,
		IncludeGoStackTrace: false,
		CallStackSize:       pluginCallStackSize,
		RegistrySize:        pluginRegistrySize,
	})
	// Cap memory so a plugin allocating in a hot loop can't OOM the worker.
	L.SetMx(pluginMaxMemoryMB)

	// Note: the package library (require/loadfile/module) is intentionally
	// NOT opened. We only allow side-effect-free, non-I/O libs here.
	libs := []struct {
		name string
		fn   lua.LGFunction
	}{
		{lua.BaseLibName, lua.OpenBase},
		{lua.TabLibName, lua.OpenTable},
		{lua.StringLibName, lua.OpenString},
		{lua.MathLibName, lua.OpenMath},
	}
	for _, lib := range libs {
		if err := L.CallByParam(lua.P{
			Fn:      L.NewFunction(lib.fn),
			NRet:    0,
			Protect: true,
		}, lua.LString(lib.name)); err != nil {
			L.Close()
			return nil, fmt.Errorf("failed to open Lua lib %s: %w", lib.name, err)
		}
	}

	// Even after skipping package lib, base lib in gopher-lua exposes
	// load/loadstring (compile-and-execute bytecode at runtime), which are
	// effectively eval. Wipe them, along with anything else a careless
	// plugin author might reach for.
	for _, g := range dangerousGlobals {
		L.SetGlobal(g, lua.LNil)
	}

	if err := L.DoFile(path); err != nil {
		L.Close()
		return nil, fmt.Errorf("failed to execute plugin: %w", err)
	}

	for _, fn := range []string{"name", "scan"} {
		val := L.GetGlobal(fn)
		if _, ok := val.(*lua.LFunction); !ok {
			L.Close()
			return nil, fmt.Errorf("plugin missing required function: %s()", fn)
		}
	}

	if err := L.CallByParam(lua.P{
		Fn:      L.GetGlobal("name"),
		NRet:    1,
		Protect: true,
	}); err != nil {
		L.Close()
		return nil, fmt.Errorf("plugin name() error: %w", err)
	}
	nameVal := L.Get(-1)
	L.Pop(1)

	name, ok := nameVal.(lua.LString)
	if !ok {
		L.Close()
		return nil, fmt.Errorf("plugin name() must return a string")
	}

	return &Plugin{
		name:   string(name),
		path:   path,
		LState: L,
	}, nil
}

// toLuaTable converts a Go map[string]string to a Lua table
func toLuaTable(L *lua.LState, m map[string]string) *lua.LTable {
	t := L.NewTable()
	for k, v := range m {
		t.RawSetString(k, lua.LString(v))
	}
	return t
}

// parseFindings converts a Lua return value into a slice of Findings
func parseFindings(L *lua.LState, val lua.LValue) []Finding {
	tbl, ok := val.(*lua.LTable)
	if !ok {
		return nil
	}

	var findings []Finding
	tbl.ForEach(func(idx lua.LValue, elem lua.LValue) {
		row, ok := elem.(*lua.LTable)
		if !ok {
			return
		}

		f := Finding{
			Title:       getLuaString(row, "title"),
			Severity:    getLuaString(row, "severity"),
			Description: getLuaString(row, "description"),
			URL:         getLuaString(row, "url"),
			Payload:     getLuaString(row, "payload"),
			Evidence:    getLuaString(row, "evidence"),
		}

		if f.Title != "" {
			findings = append(findings, f)
		}
	})

	return findings
}

// getLuaString extracts a string field from a Lua table
func getLuaString(tbl *lua.LTable, key string) string {
	val := tbl.RawGetString(key)
	if str, ok := val.(lua.LString); ok {
		return string(str)
	}
	return ""
}
