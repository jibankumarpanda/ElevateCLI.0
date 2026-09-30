package fixer

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"strconv"
	"strings"

	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// applyGoAST runs the syntax-tree-aware repairs: blocked imports, blocked
// function calls, and discarded errors.
//
// The tree is parsed once and each repair mutates it in place. If the mutated
// tree fails to print, or the printed result no longer parses, the original code
// is returned untouched and the failure is reported as unrepairable. That
// fail-closed behaviour is what makes an automated rewrite safe to run over
// untrusted generated code: a repair is either verifiably well-formed or it
// does not happen.
func (f *Fixer) applyGoAST(code string, byRule map[string][]sec.PolicyViolation) passResult {
	var out passResult

	if len(byRule["BLOCKED_IMPORT"]) == 0 &&
		len(byRule["BLOCKED_FUNCTION"]) == 0 &&
		len(byRule["UNHANDLED_ERROR"]) == 0 {
		return out
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "generated.go", code, parser.ParseComments)
	if err != nil {
		out.unrepairable = append(out.unrepairable,
			"cannot apply Go AST repairs: code does not parse, so no mechanical repair is safe")
		return out
	}

	changed := false

	if v := byRule["BLOCKED_IMPORT"]; len(v) > 0 {
		did, repairs, unfixed := f.removeBlockedImports(fset, file, v)
		changed = changed || did
		out.repairs = append(out.repairs, repairs...)
		out.unrepairable = append(out.unrepairable, unfixed...)
	}

	if v := byRule["BLOCKED_FUNCTION"]; len(v) > 0 {
		did, repairs, unfixed := f.removeBlockedCalls(fset, file, v)
		changed = changed || did
		out.repairs = append(out.repairs, repairs...)
		out.unrepairable = append(out.unrepairable, unfixed...)
	}

	if v := byRule["UNHANDLED_ERROR"]; len(v) > 0 {
		did, repairs, unfixed := f.rewrapDiscardedErrors(fset, file, v)
		changed = changed || did
		out.repairs = append(out.repairs, repairs...)
		out.unrepairable = append(out.unrepairable, unfixed...)
	}

	if !changed {
		return out
	}

	printed, err := printGoFile(fset, file)
	if err != nil {
		out.repairs = nil
		out.unrepairable = append(out.unrepairable,
			fmt.Sprintf("Go AST repair failed to render: %v (original code kept)", err))
		return out
	}

	// Re-parse the rendered source before handing it on. A patch that does not
	// parse is worse than no patch: the next round would score syntax errors
	// and report the code as broken rather than as merely unfixed.
	if _, perr := parser.ParseFile(token.NewFileSet(), "generated.go", printed, parser.ParseComments); perr != nil {
		out.repairs = nil
		out.unrepairable = append(out.unrepairable,
			fmt.Sprintf("Go AST repair produced code that no longer parses (%v); original kept", perr))
		return out
	}

	out.code = printed
	return out
}

// printGoFile renders a (possibly mutated) AST back to gofmt-shaped source.
func printGoFile(fset *token.FileSet, file *ast.File) (string, error) {
	var buf strings.Builder
	cfg := printer.Config{Mode: printer.UseSpaces | printer.TabIndent, Tabwidth: 8}
	if err := cfg.Fprint(&buf, fset, file); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// removeBlockedImports deletes import specs the policy blocks, and drops the
// import declaration entirely once it has no specs left.
//
// A blocked import whose package identifier is still referenced cannot be
// removed without deleting real logic, so it is refused and reported instead of
// being patched into code that no longer compiles.
func (f *Fixer) removeBlockedImports(fset *token.FileSet, file *ast.File, vs []sec.PolicyViolation) (bool, []Repair, []string) {
	blocked := f.policy.Rules.BlockedImports
	if len(blocked) == 0 {
		return false, nil, nil
	}

	var repairs []Repair
	var unfixed []string
	changed := false

	for _, spec := range collectImportSpecs(file) {
		if spec.Path == nil {
			continue
		}
		path := unquoteImportPath(spec.Path.Value)
		if !isBlockedImport(path, blocked) {
			continue
		}

		name := importLocalName(spec)
		if name != "" && countSelectorUses(file, name) > 0 {
			unfixed = append(unfixed, fmt.Sprintf(
				"BLOCKED_IMPORT at line %d: cannot remove import %q because %s is still referenced; "+
					"the call sites must be rewritten, which is a semantic change",
				fset.Position(spec.Pos()).Line, path, name))
			continue
		}

		line := fset.Position(spec.Pos()).Line
		removeImportSpec(file, spec)
		repairs = append(repairs, Repair{
			Kind:   RepairBlockedImport,
			Rule:   "BLOCKED_IMPORT",
			Line:   line,
			Detail: fmt.Sprintf("removed blocked import %q", path),
		})
		changed = true
	}

	return changed, repairs, unfixed
}

// removeBlockedCalls deletes statements whose only effect is calling a blocked
// function, and removes assignments whose blocked result is never read.
//
// Rewriting a call that other logic depends on would be a semantic change, so
// only two shapes are touched:
//
//   - the call is a bare statement (result discarded), so the statement exists
//     only for the effect the policy blocks;
//   - the call's result is assigned to a variable that is never read, so the
//     assignment is dead and deleting it removes nothing observable.
func (f *Fixer) removeBlockedCalls(fset *token.FileSet, file *ast.File, vs []sec.PolicyViolation) (bool, []Repair, []string) {
	blocked := f.policy.Rules.BlockedFunctions
	if len(blocked) == 0 {
		return false, nil, nil
	}

	var repairs []Repair
	var unfixed []string
	changed := false

	// Snapshot the call list: the tree is mutated while iterating.
	for _, call := range collectCallExprs(file) {
		if !isBlockedCall(call, blocked) {
			continue
		}

		line := fset.Position(call.Pos()).Line
		name := callDescription(call)

		switch parent := enclosingStatement(file, call).(type) {
		case *ast.ExprStmt:
			if !removeStatement(file, parent) {
				continue
			}
			repairs = append(repairs, Repair{
				Kind:   RepairBlockedFunction,
				Rule:   "BLOCKED_FUNCTION",
				Line:   line,
				Detail: fmt.Sprintf("removed blocked call %s whose result was discarded", name),
			})
			changed = true

		case *ast.AssignStmt:
			if len(parent.Lhs) != 1 || len(parent.Rhs) != 1 {
				continue
			}
			ident, ok := parent.Lhs[0].(*ast.Ident)
			if !ok {
				continue
			}
			// The declaration itself counts as one mention, so a count above one
			// means the value is read somewhere and cannot be dropped.
			if countIdentUses(file, ident.Name) > 1 {
				unfixed = append(unfixed, fmt.Sprintf(
					"BLOCKED_FUNCTION at line %d: %s result is assigned to %q and read elsewhere; "+
						"replacing it would fabricate a value, so a human must decide the replacement",
					line, name, ident.Name))
				continue
			}
			if !removeStatement(file, parent) {
				continue
			}
			repairs = append(repairs, Repair{
				Kind:   RepairBlockedFunction,
				Rule:   "BLOCKED_FUNCTION",
				Line:   line,
				Detail: fmt.Sprintf("removed blocked call %s assigned to unused %q", name, ident.Name),
			})
			changed = true

		default:
			unfixed = append(unfixed, fmt.Sprintf(
				"BLOCKED_FUNCTION at line %d: %s is used in a position where removing it would change "+
					"program behaviour; a human must decide the replacement",
				line, name))
		}
	}

	return changed, repairs, unfixed
}

// rewrapDiscardedErrors replaces `_ = f()` with a real error check.
//
// Only conversions whose enclosing function declares an error result are
// repaired, because that is the case where `if err := f(); err != nil { return err }`
// is provably correct. When the function returns nothing there is no error to
// propagate, and guessing a recovery path would be a semantic change, so the
// repair is refused.
func (f *Fixer) rewrapDiscardedErrors(fset *token.FileSet, file *ast.File, vs []sec.PolicyViolation) (bool, []Repair, []string) {
	var repairs []Repair
	var unfixed []string
	changed := false

	returnsError := functionsReturningError(file)

	for _, assign := range collectAssignStmts(file) {
		if !isDiscardedCall(assign) {
			continue
		}

		fn := enclosingFunc(file, assign)
		if fn == nil {
			unfixed = append(unfixed, fmt.Sprintf(
				"UNHANDLED_ERROR at line %d: discarded call is not inside a function, so no error "+
					"can be propagated", fset.Position(assign.Pos()).Line))
			continue
		}

		if !returnsError[fn.Name.Name] {
			unfixed = append(unfixed, fmt.Sprintf(
				"UNHANDLED_ERROR at line %d: function %q does not return an error, so there is nothing "+
					"to propagate; a human must decide how the failure should be handled",
				fset.Position(assign.Pos()).Line, fn.Name.Name))
			continue
		}

		if !rewrapDiscardedCall(file, assign) {
			continue
		}

		repairs = append(repairs, Repair{
			Kind:   RepairUnhandledError,
			Rule:   "UNHANDLED_ERROR",
			Line:   fset.Position(assign.Pos()).Line,
			Detail: "rewrapped a discarded error into an explicit nil check",
		})
		changed = true
	}

	return changed, repairs, unfixed
}

// rewrapDiscardedCall replaces `_ = f()` in place with
// `if err := f(); err != nil { return err }`.
func rewrapDiscardedCall(file *ast.File, assign *ast.AssignStmt) bool {
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok {
		return false
	}

	errIdent := ast.NewIdent("err")
	guard := &ast.IfStmt{
		Init: &ast.AssignStmt{
			Lhs: []ast.Expr{ast.NewIdent("err")},
			Tok: token.DEFINE,
			Rhs: []ast.Expr{call},
		},
		Cond: &ast.BinaryExpr{
			X:  ast.NewIdent("err"),
			Op: token.NEQ,
			Y:  ast.NewIdent("nil"),
		},
		Body: &ast.BlockStmt{
			List: []ast.Stmt{&ast.ReturnStmt{Results: []ast.Expr{errIdent}}},
		},
	}
	// Anchor the new statement on the original's range so the renderer keeps
	// source ordering and comment attachment stable.
	guard.Body.Lbrace = assign.Pos()
	guard.Body.Rbrace = assign.End()

	return replaceStatement(file, assign, guard)
}

// isDiscardedCall reports whether an assignment discards its right-hand call
// through the blank identifier, the pattern the policy engine flags.
func isDiscardedCall(node ast.Node) bool {
	assign, ok := node.(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return false
	}
	ident, ok := assign.Lhs[0].(*ast.Ident)
	return ok && ident.Name == "_"
}

// ─── AST traversal and mutation ──────────────────────────────────────────────

func collectImportSpecs(file *ast.File) []*ast.ImportSpec {
	out := make([]*ast.ImportSpec, 0, len(file.Imports))
	out = append(out, file.Imports...)
	return out
}

func collectCallExprs(file *ast.File) []*ast.CallExpr {
	var out []*ast.CallExpr
	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			out = append(out, call)
		}
		return true
	})
	return out
}

func collectAssignStmts(file *ast.File) []*ast.AssignStmt {
	var out []*ast.AssignStmt
	ast.Inspect(file, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok {
			out = append(out, assign)
		}
		return true
	})
	return out
}

// countIdentUses counts every mention of an identifier, including its own
// declaration. A count of one means the name is never read.
func countIdentUses(file *ast.File, name string) int {
	count := 0
	ast.Inspect(file, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && ident.Name == name {
			count++
		}
		return true
	})
	return count
}

// countSelectorUses counts qualified references such as `exec.Command`, which is
// how a still-in-use import is detected without type information.
func countSelectorUses(file *ast.File, pkg string) int {
	count := 0
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == pkg {
			// An import spec's own Path is not a selector, so any hit here is a
			// genuine use of the package qualifier.
			count++
		}
		return true
	})
	return count
}

// functionsReturningError reports which top-level functions declare at least one
// error in their result list.
func functionsReturningError(file *ast.File) map[string]bool {
	out := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Type.Results == nil {
			continue
		}
		for _, field := range fn.Type.Results.List {
			if ident, ok := field.Type.(*ast.Ident); ok && ident.Name == "error" {
				out[fn.Name.Name] = true
				break
			}
		}
	}
	return out
}

// enclosingFunc returns the top-level function whose body contains target.
func enclosingFunc(file *ast.File, target ast.Node) *ast.FuncDecl {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if containsNode(fn.Body, target) {
			return fn
		}
	}
	return nil
}

// enclosingStatement returns the statement directly containing target.
func enclosingStatement(file *ast.File, target ast.Node) ast.Stmt {
	var found ast.Stmt
	ast.Inspect(file, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		switch node := n.(type) {
		case *ast.BlockStmt:
			for _, stmt := range node.List {
				if containsNode(stmt, target) {
					found = stmt
					return false
				}
			}
		case *ast.CaseClause:
			for _, stmt := range node.Body {
				if containsNode(stmt, target) {
					found = stmt
					return false
				}
			}
		}
		return true
	})
	return found
}

// containsNode reports whether target appears anywhere inside n.
func containsNode(n, target ast.Node) bool {
	if n == nil {
		return false
	}
	found := false
	ast.Inspect(n, func(child ast.Node) bool {
		if found {
			return false
		}
		if child == target {
			found = true
			return false
		}
		return true
	})
	return found
}

// replaceStatement swaps one statement for another in its parent block or case
// clause, which is the only safe way to change a statement's type: go/ast has no
// parent pointers, so a statement cannot be mutated into a different node kind.
func replaceStatement(file *ast.File, old ast.Stmt, next ast.Stmt) bool {
	replaced := false
	ast.Inspect(file, func(n ast.Node) bool {
		if replaced {
			return false
		}
		switch node := n.(type) {
		case *ast.BlockStmt:
			for i, stmt := range node.List {
				if stmt == old {
					node.List[i] = next
					replaced = true
					return false
				}
			}
		case *ast.CaseClause:
			for i, stmt := range node.Body {
				if stmt == old {
					node.Body[i] = next
					replaced = true
					return false
				}
			}
		}
		return true
	})
	return replaced
}

// removeStatement deletes a statement from its parent block or case clause. A
// block emptied this way becomes invalid Go, so it is replaced with a `pass`
// statement to keep the source parseable.
func removeStatement(file *ast.File, target ast.Stmt) bool {
	removed := false
	ast.Inspect(file, func(n ast.Node) bool {
		if removed {
			return false
		}
		switch node := n.(type) {
		case *ast.BlockStmt:
			kept, dropped := pruneStmts(node.List, target)
			if dropped {
				node.List = keepNonEmpty(kept)
				removed = true
				return false
			}
		case *ast.CaseClause:
			kept, dropped := pruneStmts(node.Body, target)
			if dropped {
				node.Body = keepNonEmpty(kept)
				removed = true
				return false
			}
		}
		return true
	})
	return removed
}

func pruneStmts(stmts []ast.Stmt, target ast.Stmt) ([]ast.Stmt, bool) {
	var kept []ast.Stmt
	for _, stmt := range stmts {
		if stmt == target {
			continue
		}
		kept = append(kept, stmt)
	}
	return kept, len(kept) != len(stmts)
}

// keepNonEmpty substitutes `pass` for a block left with no statements, because an
// empty Go block does not parse.
func keepNonEmpty(stmts []ast.Stmt) []ast.Stmt {
	if len(stmts) > 0 {
		return stmts
	}
	return []ast.Stmt{&ast.EmptyStmt{Semicolon: token.NoPos, Implicit: true}}
}

// removeImportSpec deletes a spec from its declaration and drops the declaration
// when it becomes empty, so no dangling `import ()` is left behind.
func removeImportSpec(file *ast.File, target *ast.ImportSpec) {
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.IMPORT {
			continue
		}
		kept, dropped := pruneSpecs(gd.Specs, target)
		if !dropped {
			continue
		}
		if len(kept) == 0 {
			removeDecl(file, gd)
		} else {
			gd.Specs = kept
		}
		refreshFileImports(file)
		return
	}
}

func pruneSpecs(specs []ast.Spec, target ast.Spec) ([]ast.Spec, bool) {
	var kept []ast.Spec
	for _, spec := range specs {
		if spec == target {
			continue
		}
		kept = append(kept, spec)
	}
	return kept, len(kept) != len(specs)
}

// refreshFileImports rebuilds file.Imports from the declarations that survive, so
// later passes observe the same view the printer will render.
func refreshFileImports(file *ast.File) {
	file.Imports = nil
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.IMPORT {
			continue
		}
		for _, spec := range gd.Specs {
			if is, ok := spec.(*ast.ImportSpec); ok {
				file.Imports = append(file.Imports, is)
			}
		}
	}
}

func removeDecl(file *ast.File, target ast.Decl) {
	var kept []ast.Decl
	for _, decl := range file.Decls {
		if decl == target {
			continue
		}
		kept = append(kept, decl)
	}
	file.Decls = kept
}

// ─── Import and call matching ────────────────────────────────────────────────

func importLocalName(spec *ast.ImportSpec) string {
	if spec.Name != nil {
		return spec.Name.Name
	}
	if spec.Path == nil {
		return ""
	}
	path := unquoteImportPath(spec.Path.Value)
	idx := strings.LastIndex(path, "/")
	if idx < 0 {
		return path
	}
	return path[idx+1:]
}

func unquoteImportPath(literal string) string {
	if unquoted, err := strconv.Unquote(literal); err == nil {
		return unquoted
	}
	if len(literal) >= 2 {
		return literal[1 : len(literal)-1]
	}
	return literal
}

func isBlockedImport(path string, blocked []string) bool {
	for _, b := range blocked {
		if path == b {
			return true
		}
		if strings.HasPrefix(path, b+"/") {
			return true
		}
	}
	return false
}

// isBlockedCall matches a call against the configured block list using the same
// three shapes the policy engine uses: the bare selector name, the fully
// qualified name, and the package prefix alone (so blocking "exec" catches
// every exec.* call).
func isBlockedCall(call *ast.CallExpr, blocked []string) bool {
	bare, qualified := callNames(call)
	for _, b := range blocked {
		if bare == b || qualified == b {
			return true
		}
		if qualified == b+"."+bare {
			return true
		}
	}
	return false
}

func callNames(call *ast.CallExpr) (bare, qualified string) {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name, fun.Name
	case *ast.SelectorExpr:
		if pkg, ok := fun.X.(*ast.Ident); ok {
			return fun.Sel.Name, pkg.Name + "." + fun.Sel.Name
		}
		return fun.Sel.Name, fun.Sel.Name
	}
	return "", ""
}

func callDescription(call *ast.CallExpr) string {
	if _, qualified := callNames(call); qualified != "" {
		return qualified + "()"
	}
	return "call"
}
