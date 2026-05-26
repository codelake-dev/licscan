package lsp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/codelake-dev/licscan/internal/scanner"
	"github.com/codelake-dev/licscan/internal/scanner/detectors"
	"github.com/codelake-dev/licscan/internal/scanner/policy"
	"github.com/codelake-dev/licscan/internal/version"
)

var defaultDetectors = []scanner.Detector{
	&detectors.GoMod{},
	&detectors.Npm{},
	&detectors.Composer{},
	&detectors.Cargo{},
	&detectors.Gem{},
	&detectors.Pip{},
}

// manifestFiles are the filenames the LSP watches for scan triggers.
var manifestFiles = map[string]bool{
	"go.mod": true, "go.sum": true,
	"package.json": true, "package-lock.json": true,
	"composer.json": true, "composer.lock": true,
	"Cargo.toml": true, "Cargo.lock": true,
	"Gemfile": true, "Gemfile.lock": true,
	"pyproject.toml": true, "poetry.lock": true, "Pipfile.lock": true, "requirements.txt": true,
	"pom.xml": true,
}

// Server is the licscan LSP server.
type Server struct {
	transport *transport
	log       io.Writer
	rootPath  string

	mu       sync.Mutex
	docs     map[string]string // uri → content
	lastScan *scanner.Result
}

// Run starts the LSP server on the given reader/writer (typically stdin/stdout).
// The log writer receives debug messages (typically stderr).
func Run(r io.Reader, w io.Writer, log io.Writer) error {
	s := &Server{
		transport: newTransport(r, w),
		log:       log,
		docs:      make(map[string]string),
	}
	return s.loop()
}

func (s *Server) logf(format string, args ...interface{}) {
	fmt.Fprintf(s.log, "[licscan-lsp] "+format+"\n", args...)
}

func (s *Server) loop() error {
	for {
		raw, err := s.transport.read()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		var msg jsonRPCMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			s.logf("parse error: %v", err)
			continue
		}

		if err := s.handle(msg, raw); err != nil {
			s.logf("handler error: %v", err)
		}
	}
}

func (s *Server) handle(msg jsonRPCMessage, raw json.RawMessage) error {
	switch msg.Method {
	case "initialize":
		return s.handleInitialize(msg, raw)
	case "initialized":
		return s.handleInitialized()
	case "shutdown":
		return s.respond(msg.ID, nil)
	case "exit":
		os.Exit(0)
	case "textDocument/didOpen":
		return s.handleDidOpen(raw)
	case "textDocument/didSave":
		return s.handleDidSave(raw)
	case "textDocument/didClose":
		return s.handleDidClose(raw)
	case "textDocument/inlayHint":
		return s.handleInlayHint(msg, raw)
	}
	if msg.ID != nil {
		return s.respond(msg.ID, nil)
	}
	return nil
}

func (s *Server) handleInitialize(msg jsonRPCMessage, raw json.RawMessage) error {
	var full struct {
		Params initializeParams `json:"params"`
	}
	if err := json.Unmarshal(raw, &full); err == nil {
		s.rootPath = uriToPath(full.Params.RootURI)
		if s.rootPath == "" {
			s.rootPath = full.Params.RootPath
		}
	}

	s.logf("initialize: root=%s", s.rootPath)

	return s.respond(msg.ID, initializeResult{
		Capabilities: serverCapabilities{
			TextDocumentSync:   1, // Full sync
			InlayHintProvider:  true,
			CodeActionProvider: false,
		},
		ServerInfo: serverInfo{
			Name:    "licscan",
			Version: version.Short(),
		},
	})
}

func (s *Server) handleInitialized() error {
	s.logf("initialized, scanning workspace...")
	return s.scanAndPublish()
}

func (s *Server) handleDidOpen(raw json.RawMessage) error {
	var full struct {
		Params didOpenParams `json:"params"`
	}
	if err := json.Unmarshal(raw, &full); err != nil {
		return err
	}

	uri := full.Params.TextDocument.URI
	s.mu.Lock()
	s.docs[uri] = full.Params.TextDocument.Text
	s.mu.Unlock()

	if isManifestURI(uri) {
		return s.scanAndPublish()
	}
	return nil
}

func (s *Server) handleDidSave(raw json.RawMessage) error {
	var full struct {
		Params didSaveParams `json:"params"`
	}
	if err := json.Unmarshal(raw, &full); err != nil {
		return err
	}

	if isManifestURI(full.Params.TextDocument.URI) {
		return s.scanAndPublish()
	}
	return nil
}

func (s *Server) handleDidClose(raw json.RawMessage) error {
	var full struct {
		Params didCloseParams `json:"params"`
	}
	if err := json.Unmarshal(raw, &full); err != nil {
		return err
	}

	s.mu.Lock()
	delete(s.docs, full.Params.TextDocument.URI)
	s.mu.Unlock()
	return nil
}

func (s *Server) handleInlayHint(msg jsonRPCMessage, raw json.RawMessage) error {
	var full struct {
		Params inlayHintParams `json:"params"`
	}
	if err := json.Unmarshal(raw, &full); err != nil {
		return s.respond(msg.ID, []inlayHint{})
	}

	uri := full.Params.TextDocument.URI
	filePath := uriToPath(uri)

	s.mu.Lock()
	content, hasContent := s.docs[uri]
	result := s.lastScan
	s.mu.Unlock()

	if result == nil {
		return s.respond(msg.ID, []inlayHint{})
	}

	if !hasContent {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return s.respond(msg.ID, []inlayHint{})
		}
		content = string(data)
	}

	hints := buildInlayHints(filePath, content, result)
	return s.respond(msg.ID, hints)
}

func (s *Server) scanAndPublish() error {
	root := s.rootPath
	if root == "" {
		return nil
	}

	result, err := scanner.New(defaultDetectors...).Scan(root)
	if err != nil {
		s.logf("scan error: %v", err)
		return nil
	}

	pol, err := policy.Load(root)
	if err != nil {
		s.logf("policy error: %v", err)
		pol = policy.Default()
	}
	pol.Apply(result)

	projectLicense := policy.DetectProjectLicense(root, pol)
	policy.CheckCompatibility(result, projectLicense)

	s.mu.Lock()
	s.lastScan = result
	s.mu.Unlock()

	s.logf("scanned: %d deps, %d detectors", len(result.Dependencies), len(result.Detectors))

	diagnosticsByURI := buildDiagnostics(root, result)

	for uri, diags := range diagnosticsByURI {
		if err := s.notify("textDocument/publishDiagnostics", publishDiagnosticsParams{
			URI:         uri,
			Diagnostics: diags,
		}); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) respond(id *int, result interface{}) error {
	return s.transport.write(jsonRPCMessage{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
}

func (s *Server) notify(method string, params interface{}) error {
	return s.transport.write(jsonRPCMessage{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
	})
}

func uriToPath(uri string) string {
	if strings.HasPrefix(uri, "file://") {
		u, err := url.Parse(uri)
		if err != nil {
			return strings.TrimPrefix(uri, "file://")
		}
		return u.Path
	}
	return uri
}

func pathToURI(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	return "file://" + abs
}

func isManifestURI(uri string) bool {
	path := uriToPath(uri)
	base := filepath.Base(path)
	return manifestFiles[base]
}
