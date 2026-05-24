package format

import (
	"encoding/json"
	"io"

	"github.com/codelake-ai/licscan/internal/scanner"
)

// JSON renders the Result as pretty-printed JSON. The schema is stable
// — CI scripts can rely on the field names and types.
func JSON(w io.Writer, result *scanner.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(result)
}
