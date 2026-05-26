package lsp

// JSON-RPC 2.0 message types.

type jsonRPCMessage struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      *int        `json:"id,omitempty"`
	Method  string      `json:"method,omitempty"`
	Params  interface{} `json:"params,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// LSP Initialize

type initializeParams struct {
	RootURI  string `json:"rootUri"`
	RootPath string `json:"rootPath"`
}

type initializeResult struct {
	Capabilities serverCapabilities `json:"capabilities"`
	ServerInfo   serverInfo         `json:"serverInfo"`
}

type serverCapabilities struct {
	TextDocumentSync   int                `json:"textDocumentSync"`
	DiagnosticProvider *diagnosticOptions `json:"diagnosticProvider,omitempty"`
	InlayHintProvider  bool               `json:"inlayHintProvider,omitempty"`
	CodeActionProvider bool               `json:"codeActionProvider,omitempty"`
}

type diagnosticOptions struct {
	Identifier            string `json:"identifier"`
	InterFileDependencies bool   `json:"interFileDependencies"`
	WorkspaceDiagnostics  bool   `json:"workspaceDiagnostics"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Text Document types

type textDocumentItem struct {
	URI        string `json:"uri"`
	LanguageID string `json:"languageId"`
	Version    int    `json:"version"`
	Text       string `json:"text"`
}

type didOpenParams struct {
	TextDocument textDocumentItem `json:"textDocument"`
}

type didSaveParams struct {
	TextDocument textDocumentIdentifier `json:"textDocument"`
}

type didCloseParams struct {
	TextDocument textDocumentIdentifier `json:"textDocument"`
}

type textDocumentIdentifier struct {
	URI string `json:"uri"`
}

// Diagnostics

type publishDiagnosticsParams struct {
	URI         string       `json:"uri"`
	Diagnostics []diagnostic `json:"diagnostics"`
}

type diagnostic struct {
	Range    diagRange       `json:"range"`
	Severity int             `json:"severity"`
	Source   string          `json:"source"`
	Code     string          `json:"code,omitempty"`
	Message  string          `json:"message"`
	Data     *diagnosticData `json:"data,omitempty"`
}

type diagnosticData struct {
	License   string `json:"license"`
	Risk      string `json:"risk"`
	Verdict   string `json:"verdict"`
	Ecosystem string `json:"ecosystem"`
}

type diagRange struct {
	Start position `json:"start"`
	End   position `json:"end"`
}

type position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

// Inlay Hints (LSP 3.17)

type inlayHintParams struct {
	TextDocument textDocumentIdentifier `json:"textDocument"`
	Range        diagRange              `json:"range"`
}

type inlayHint struct {
	Position     position `json:"position"`
	Label        string   `json:"label"`
	Kind         int      `json:"kind,omitempty"`
	Tooltip      string   `json:"tooltip,omitempty"`
	PaddingLeft  bool     `json:"paddingLeft,omitempty"`
	PaddingRight bool     `json:"paddingRight,omitempty"`
}

// LSP Severity constants
const (
	severityError       = 1
	severityWarning     = 2
	severityInformation = 3
	severityHint        = 4
)
