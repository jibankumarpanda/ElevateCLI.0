package security

import (
	"fmt"
	"strings"

	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// langSyntax describes the lexical rules needed to validate that a source file
// is structurally sound: which strings and comments can hide brackets, and
// which delimiters open and close strings.
type langSyntax struct {
	lineComments  []string
	blockComments [][2]string
	// quotes are the single-character string delimiters for the language.
	quotes []byte
	// tripleQuotes enables Python-style triple-quoted strings.
	tripleQuotes bool
	// templateQuotes are delimiters that may span newlines (Go raw strings,
	// JS template literals).
	templateQuotes []byte
}

var syntaxConfigs = map[string]langSyntax{
	"go": {
		lineComments:   []string{"//"},
		blockComments:  [][2]string{{"/*", "*/"}},
		quotes:         []byte{'"', '\''},
		templateQuotes: []byte{'`'},
	},
	"python": {
		lineComments: []string{"#"},
		quotes:       []byte{'"', '\''},
		tripleQuotes: true,
	},
	"javascript": {
		lineComments:   []string{"//"},
		blockComments:  [][2]string{{"/*", "*/"}},
		quotes:         []byte{'"', '\''},
		templateQuotes: []byte{'`'},
	},
}

func init() {
	syntaxConfigs["golang"] = syntaxConfigs["go"]
	syntaxConfigs["python3"] = syntaxConfigs["python"]
	syntaxConfigs["js"] = syntaxConfigs["javascript"]
	syntaxConfigs["typescript"] = syntaxConfigs["javascript"]
	syntaxConfigs["ts"] = syntaxConfigs["javascript"]
	syntaxConfigs["tsx"] = syntaxConfigs["javascript"]
	syntaxConfigs["jsx"] = syntaxConfigs["javascript"]
}

// syntaxProblem is an internal lexical error located at a line.
type syntaxProblem struct {
	line int
	msg  string
}

// validateSyntax performs language-aware structural validation of source code.
// It catches unbalanced brackets and unterminated strings/comments that a
// pattern matcher cannot see, and returns them as high-severity findings so a
// syntactically broken generation is never silently approved. Languages without
// a configured validator yield no findings.
func validateSyntax(code, language string) []sec.Finding {
	cfg, ok := syntaxConfigs[strings.ToLower(language)]
	if !ok {
		return nil
	}
	problems := scanSyntax(code, cfg)
	if len(problems) == 0 {
		return nil
	}
	lines := strings.Split(code, "\n")
	findings := make([]sec.Finding, 0, len(problems))
	for i, p := range problems {
		snippet := ""
		if p.line >= 1 && p.line <= len(lines) {
			snippet = strings.TrimSpace(lines[p.line-1])
		}
		findings = append(findings, sec.Finding{
			ID:          fmt.Sprintf("syntax-error-%d", i+1),
			RuleID:      "SYNTAX",
			Title:       "Generated code has syntax errors",
			Severity:    sec.SeverityHigh,
			Source:      "custom-ast",
			Description: fmt.Sprintf("Line %d: %s", p.line, p.msg),
			Suggestion:  "Regenerate with a more specific prompt.",
			Code:        snippet,
			Line:        p.line,
		})
	}
	return findings
}

// scanSyntax walks the source applying the language's lexical rules, tracking
// open brackets and string/comment state.
func scanSyntax(code string, cfg langSyntax) []syntaxProblem {
	var problems []syntaxProblem
	type openBracket struct {
		ch   byte
		line int
	}
	var stack []openBracket
	line := 1
	i := 0
	n := len(code)

	match := func(pairs [][2]string) (int, bool) {
		for _, p := range pairs {
			if strings.HasPrefix(code[i:], p[0]) {
				return len(p[0]), true
			}
		}
		return 0, false
	}

	for i < n {
		c := code[i]

		if c == '\n' {
			line++
			i++
			continue
		}

		// Comments.
		if ll, ok := match(textPairs(cfg.lineComments)); ok {
			for i < n && code[i] != '\n' {
				i++
			}
			_ = ll
			continue
		}
		if bl, ok := match(cfg.blockComments); ok {
			start := line
			i += bl
			closed := false
			for i < n {
				if strings.HasPrefix(code[i:], "*/") {
					i += 2
					closed = true
					break
				}
				if code[i] == '\n' {
					line++
				}
				i++
			}
			if !closed {
				problems = append(problems, syntaxProblem{start, "unterminated block comment"})
			}
			continue
		}

		// Python-style triple-quoted strings.
		if cfg.tripleQuotes {
			if i+2 < n && (c == '"' || c == '\'') && code[i+1] == c && code[i+2] == c {
				start := line
				i += 3
				closed := false
				for i < n {
					if i+2 < n && code[i] == c && code[i+1] == c && code[i+2] == c {
						i += 3
						closed = true
						break
					}
					if code[i] == '\n' {
						line++
					}
					i++
				}
				if !closed {
					problems = append(problems, syntaxProblem{start, "unterminated triple-quoted string"})
				}
				continue
			}
		}

		// Template / raw strings (may span newlines; escapes ignored).
		if containsByte(cfg.templateQuotes, c) {
			start := line
			i++
			closed := false
			for i < n {
				if code[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				if code[i] == c {
					i++
					closed = true
					break
				}
				if code[i] == '\n' {
					line++
				}
				i++
			}
			if !closed {
				problems = append(problems, syntaxProblem{start, "unterminated string literal"})
			}
			continue
		}

		// Single-line string literals.
		if containsByte(cfg.quotes, c) {
			start := line
			i++
			closed := false
			for i < n {
				if code[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				if code[i] == c {
					i++
					closed = true
					break
				}
				if code[i] == '\n' {
					break
				}
				i++
			}
			if !closed {
				problems = append(problems, syntaxProblem{start, "unterminated string literal"})
			}
			continue
		}

		// Brackets.
		switch c {
		case '(', '[', '{':
			stack = append(stack, openBracket{c, line})
		case ')', ']', '}':
			want := matchingOpen(c)
			if len(stack) == 0 {
				problems = append(problems, syntaxProblem{line, fmt.Sprintf("unexpected '%c'", c)})
			} else if top := stack[len(stack)-1]; top.ch != want {
				problems = append(problems, syntaxProblem{
					line, fmt.Sprintf("mismatched '%c' (expected closing for '%c' from line %d)", c, top.ch, top.line)})
				stack = stack[:len(stack)-1]
			} else {
				stack = stack[:len(stack)-1]
			}
		}
		i++
	}

	for _, b := range stack {
		problems = append(problems, syntaxProblem{b.line, fmt.Sprintf("unclosed '%c'", b.ch)})
	}
	return problems
}

func textPairs(ss []string) [][2]string {
	pairs := make([][2]string, 0, len(ss))
	for _, s := range ss {
		pairs = append(pairs, [2]string{s, ""})
	}
	return pairs
}

func containsByte(bs []byte, b byte) bool {
	for _, x := range bs {
		if x == b {
			return true
		}
	}
	return false
}

func matchingOpen(close byte) byte {
	switch close {
	case ')':
		return '('
	case ']':
		return '['
	default:
		return '{'
	}
}
