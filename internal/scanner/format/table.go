// Package format renders a scanner.Result to a target output format.
package format

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/codelake-dev/licscan/internal/scanner"
)

// Table renders a human-readable terminal table.
//
// Dependencies are sorted by descending risk first, then alphabetically
// by name — so the things a human needs to look at appear at the top.
func Table(w io.Writer, result *scanner.Result) error {
	if _, err := fmt.Fprintf(w, "Scan path: %s\n", result.ScanPath); err != nil {
		return err
	}
	if len(result.Detectors) > 0 {
		if _, err := fmt.Fprintf(w, "Detectors: %s\n", strings.Join(result.Detectors, ", ")); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	if len(result.Dependencies) == 0 {
		if _, err := fmt.Fprintln(w, "No dependencies found."); err != nil {
			return err
		}
	} else {
		if err := writeDependencyTable(w, result.Dependencies); err != nil {
			return err
		}
	}

	if err := writeSummary(w, result.Summary); err != nil {
		return err
	}

	if len(result.Errors) > 0 {
		if _, err := fmt.Fprintln(w, "\nDetector errors:"); err != nil {
			return err
		}
		for _, e := range result.Errors {
			if _, err := fmt.Fprintf(w, "  - %s\n", e); err != nil {
				return err
			}
		}
	}

	return nil
}

func writeDependencyTable(w io.Writer, deps []scanner.Dependency) error {
	sorted := make([]scanner.Dependency, len(deps))
	copy(sorted, deps)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].PrimaryRisk() != sorted[j].PrimaryRisk() {
			return sorted[i].PrimaryRisk() > sorted[j].PrimaryRisk()
		}
		return sorted[i].Name < sorted[j].Name
	})

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "RISK\tPACKAGE\tVERSION\tLICENSE\tDIRECT\tECOSYSTEM"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(tw, "----\t-------\t-------\t-------\t------\t---------"); err != nil {
		return err
	}
	for _, d := range sorted {
		risk := d.PrimaryRisk()
		direct := "no"
		if d.Direct {
			direct = "yes"
		}
		if _, err := fmt.Fprintf(tw, "%s %s\t%s\t%s\t%s\t%s\t%s\n",
			risk.Emoji(), risk.String(), d.Name, d.Version, d.PrimaryLicense(), direct, d.Ecosystem); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func writeSummary(w io.Writer, summary map[string]int) error {
	if _, err := fmt.Fprintln(w, "\nSummary:"); err != nil {
		return err
	}
	// Print in a stable, risk-order rather than map-iteration order.
	order := []scanner.RiskLevel{
		scanner.RiskViral,
		scanner.RiskStrongCopyleft,
		scanner.RiskWeakCopyleft,
		scanner.RiskPermissive,
		scanner.RiskUnknown,
	}
	for _, lvl := range order {
		label := lvl.String()
		count := summary[label]
		if _, err := fmt.Fprintf(w, "  %s %-22s %d\n", lvl.Emoji(), label, count); err != nil {
			return err
		}
	}
	return nil
}
