package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/theworker02/wiretap/internal/capture"
	"github.com/theworker02/wiretap/schema"
)

type exampleCatalog struct {
	Version  int             `yaml:"version" json:"version"`
	Examples []catalogEntry  `yaml:"examples" json:"examples"`
}

type catalogEntry struct {
	ID         string `yaml:"id" json:"id"`
	Path       string `yaml:"path" json:"path"`
	Title      string `yaml:"title" json:"title"`
	Summary    string `yaml:"summary" json:"summary"`
	Difficulty string `yaml:"difficulty" json:"difficulty"`
}

func cmdCatalog() *cobra.Command {
	return &cobra.Command{
		Use:   "catalog",
		Short: "List bundled example corpora from examples/catalog.yaml",
		Long:  "Reads the product example catalog and prints paths, difficulty, and summaries.",
		Example: `  wiretap catalog
  wiretap catalog --format json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			path := findCatalog()
			if path == "" {
				return fmt.Errorf("examples/catalog.yaml not found (run from the Wiretap checkout)")
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			var cat exampleCatalog
			if err := yaml.Unmarshal(b, &cat); err != nil {
				return err
			}
			if strings.EqualFold(flagFormat, "json") {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(cat)
			}
			fmt.Printf("Wiretap examples (catalog v%d)\n\n", cat.Version)
			for _, e := range cat.Examples {
				fmt.Printf("  %-16s  %-12s  %s\n", e.ID, e.Difficulty, e.Title)
				fmt.Printf("  %-16s  %s\n", "", e.Path)
				fmt.Printf("  %-16s  %s\n\n", "", e.Summary)
			}
			fmt.Println("Try: wiretap analyze examples/mystery/captures.hex")
			return nil
		},
	}
}

func findCatalog() string {
	dir, _ := os.Getwd()
	for i := 0; i < 8; i++ {
		p := filepath.Join(dir, "examples", "catalog.yaml")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

func cmdLint() *cobra.Command {
	return &cobra.Command{
		Use:   "lint <schema.yaml|schema.json>",
		Short: "Lint a schema for hygiene issues (overlaps, missing endian, unnamed fields)",
		Long:  "Runs structural Validate first, then Lint for non-fatal quality warnings. Exit code 1 only when Validate fails.",
		Args:  cobra.ExactArgs(1),
		Example: `  wiretap lint schemas/draft.yaml
  wiretap schema infer captures.hex > draft.yaml && wiretap lint draft.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := schema.LoadFile(args[0], flagSchemaFmt)
			if err != nil {
				return err
			}
			errs := schema.Validate(s)
			issues := schema.Lint(s)
			for _, e := range errs {
				fmt.Fprintf(os.Stderr, "error: %v\n", e)
			}
			for _, i := range issues {
				fmt.Printf("%s\n", i)
			}
			if len(errs) > 0 {
				return fmt.Errorf("lint: %d validate error(s), %d warning(s)", len(errs), len(issues))
			}
			if len(issues) == 0 {
				fmt.Println("lint: clean")
			} else {
				fmt.Printf("lint: %d warning(s), 0 errors\n", len(issues))
			}
			return nil
		},
	}
}

func cmdFormat() *cobra.Command {
	var width int
	var upper bool
	var hexStr, outPath string
	c := &cobra.Command{
		Use:     "format [path|-]",
		Aliases: []string{"fmt-hex", "normalize"},
		Short:   "Normalize and pretty-print hex input (spaces / 0x / colons → canonical rows)",
		Long:    "Parses tolerant hex and writes canonical spaced hex. Does not run inference.",
		Example: `  wiretap format --hex "8a:01:00:0c"
  wiretap format captures.hex -o clean.hex`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var raw string
			switch {
			case hexStr != "":
				raw = hexStr
			case len(args) == 0 || args[0] == "-":
				b, err := io.ReadAll(os.Stdin)
				if err != nil {
					return err
				}
				raw = string(b)
			default:
				b, err := os.ReadFile(args[0])
				if err != nil {
					return err
				}
				raw = string(b)
			}
			var out strings.Builder
			wrote := 0
			for _, line := range strings.Split(raw, "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				data, err := capture.ParseAuto(line)
				if err != nil {
					continue
				}
				out.WriteString(prettyHex(data, width, upper))
				out.WriteByte('\n')
				wrote++
			}
			if wrote == 0 {
				data, err := capture.ParseAuto(raw)
				if err != nil {
					return err
				}
				out.WriteString(prettyHex(data, width, upper))
				out.WriteByte('\n')
			}
			if outPath == "" || outPath == "-" {
				_, err := os.Stdout.WriteString(out.String())
				return err
			}
			if err := os.WriteFile(outPath, []byte(out.String()), 0o644); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "wrote %s\n", outPath)
			return nil
		},
	}
	c.Flags().StringVar(&hexStr, "hex", "", "hex string instead of file/stdin")
	c.Flags().StringVarP(&outPath, "output", "o", "", "output file (default stdout)")
	c.Flags().IntVar(&width, "width", 16, "bytes per output row (0 = single line)")
	c.Flags().BoolVar(&upper, "upper", true, "uppercase hex digits")
	return c
}

func prettyHex(data []byte, width int, upper bool) string {
	enc := hex.EncodeToString(data)
	if upper {
		enc = strings.ToUpper(enc)
	} else {
		enc = strings.ToLower(enc)
	}
	parts := make([]string, 0, len(data))
	for i := 0; i+2 <= len(enc); i += 2 {
		parts = append(parts, enc[i:i+2])
	}
	if width <= 0 {
		return strings.Join(parts, " ")
	}
	var b strings.Builder
	for i := 0; i < len(parts); i += width {
		if i > 0 {
			b.WriteByte('\n')
		}
		end := i + width
		if end > len(parts) {
			end = len(parts)
		}
		fmt.Fprintf(&b, "%04X  %s", i, strings.Join(parts[i:end], " "))
	}
	return b.String()
}
