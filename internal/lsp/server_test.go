package lsp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"runtime"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codelake-dev/licscan/internal/scanner"
)

func TestTransportReadWrite(t *testing.T) {
	msg := jsonRPCMessage{
		JSONRPC: "2.0",
		Method:  "test",
	}

	var buf bytes.Buffer
	tr := newTransport(nil, &buf)
	require.NoError(t, tr.write(msg))

	written := buf.String()
	assert.Contains(t, written, "Content-Length:")
	assert.Contains(t, written, `"jsonrpc":"2.0"`)

	tr2 := newTransport(strings.NewReader(written), nil)
	raw, err := tr2.read()
	require.NoError(t, err)

	var parsed jsonRPCMessage
	require.NoError(t, json.Unmarshal(raw, &parsed))
	assert.Equal(t, "2.0", parsed.JSONRPC)
	assert.Equal(t, "test", parsed.Method)
}

func TestInitializeResponse(t *testing.T) {
	initReq := jsonRPCMessage{
		JSONRPC: "2.0",
		ID:      intPtr(1),
		Method:  "initialize",
		Params: initializeParams{
			RootURI: "file:///tmp/test-project",
		},
	}
	shutdownReq := jsonRPCMessage{
		JSONRPC: "2.0",
		ID:      intPtr(2),
		Method:  "shutdown",
	}

	input := encodeMessages(t, initReq, shutdownReq)
	var output bytes.Buffer

	err := Run(input, &output, io.Discard)
	require.NoError(t, err)

	responses := decodeResponses(t, output.String())
	require.GreaterOrEqual(t, len(responses), 1)

	var initResult initializeResult
	raw, err := json.Marshal(responses[0].Result)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &initResult))

	assert.Equal(t, "licscan", initResult.ServerInfo.Name)
	assert.Equal(t, 1, initResult.Capabilities.TextDocumentSync)
	assert.True(t, initResult.Capabilities.InlayHintProvider)
}

func TestVerdictToSeverity(t *testing.T) {
	tests := []struct {
		verdict  string
		expected int
	}{
		{"deny", severityError},
		{"incompatible", severityError},
		{"warn", severityWarning},
		{"allow", severityInformation},
		{"exempt", severityInformation},
	}

	for _, tt := range tests {
		t.Run(tt.verdict, func(t *testing.T) {
			got := verdictToSeverity(tt.verdict, 0)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestIsManifestURI(t *testing.T) {
	assert.True(t, isManifestURI("file:///project/go.mod"))
	assert.True(t, isManifestURI("file:///project/package.json"))
	assert.True(t, isManifestURI("file:///project/Cargo.toml"))
	assert.True(t, isManifestURI("file:///project/pom.xml"))
	assert.False(t, isManifestURI("file:///project/main.go"))
	assert.False(t, isManifestURI("file:///project/README.md"))
}

func TestURIConversion(t *testing.T) {
	if runtime.GOOS == "windows" {
		assert.Contains(t, uriToPath("file:///C:/tmp/project"), "tmp/project")
		assert.Contains(t, pathToURI("C:\\tmp\\project"), "file://")
	} else {
		assert.Equal(t, "/tmp/project", uriToPath("file:///tmp/project"))
		assert.Contains(t, pathToURI("/tmp/project"), "file:///tmp/project")
	}
}

func TestFindDepLine(t *testing.T) {
	lines := []string{
		`module example.com/myapp`,
		``,
		`go 1.22`,
		``,
		`require (`,
		`	github.com/spf13/cobra v1.8.0`,
		`	golang.org/x/mod v0.21.0`,
		`)`,
	}

	dep := scanner.Dependency{Name: "github.com/spf13/cobra", Version: "v1.8.0"}
	line, col, _ := findDepLine(lines, dep)
	assert.Equal(t, 5, line)
	assert.GreaterOrEqual(t, col, 0)
}

func TestFindDepLinePackageJSON(t *testing.T) {
	lines := []string{
		`{`,
		`  "dependencies": {`,
		`    "lodash": "^4.17.21",`,
		`    "react": "^18.3.1"`,
		`  }`,
		`}`,
	}

	dep := scanner.Dependency{Name: "lodash", Version: "4.17.21"}
	line, _, _ := findDepLine(lines, dep)
	assert.Equal(t, 2, line)
}

func intPtr(i int) *int { return &i }

func encodeMessages(t *testing.T, msgs ...jsonRPCMessage) io.Reader {
	t.Helper()
	var buf bytes.Buffer
	for _, msg := range msgs {
		body, err := json.Marshal(msg)
		require.NoError(t, err)
		header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body))
		buf.WriteString(header)
		buf.Write(body)
	}
	return &buf
}

func decodeResponses(t *testing.T, raw string) []jsonRPCMessage {
	t.Helper()
	var results []jsonRPCMessage
	reader := newTransport(strings.NewReader(raw), nil)
	for {
		body, err := reader.read()
		if err != nil {
			break
		}
		var msg jsonRPCMessage
		if json.Unmarshal(body, &msg) == nil {
			results = append(results, msg)
		}
	}
	return results
}
