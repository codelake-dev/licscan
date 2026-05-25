package banner

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLogoIsNineLines(t *testing.T) {
	lines := strings.Split(strings.Trim(Logo, "\n"), "\n")
	require.Len(t, lines, 8, "logo must remain exactly 8 lines tall")
}

func TestAttributionContainsBothLegalEntities(t *testing.T) {
	require.Contains(t, Attribution, "codelake Technologies LLC")
	require.Contains(t, Attribution, "Akyros Labs")
}

func TestRenderEmitsLogoAttributionAndTagline(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Render(&buf))

	out := buf.String()
	require.Contains(t, out, "████", "logo must be rendered")
	require.Contains(t, out, Attribution, "attribution must be rendered")
	require.Contains(t, out, Tagline, "tagline must be rendered")
}

func TestRenderPropagatesWriterErrors(t *testing.T) {
	err := Render(failingWriter{})
	require.Error(t, err)
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errFailingWrite
}

var errFailingWrite = &writerError{msg: "writer failed"}

type writerError struct{ msg string }

func (e *writerError) Error() string { return e.msg }
