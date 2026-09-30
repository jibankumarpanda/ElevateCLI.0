package fixer

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// reduceComplexity lowers the cyclomatic complexity of over-limit Go functions by
// extracting boolean sub-conditions into named predicate helpers.
//
// Each extracted `a > 0 && b > 0` becomes `fn_cond1(a, b)`, which removes every
// short-circuit operator from the original function and adds a single decision
// point to a new helper. The reduction is behaviour-preserving: `&&` and `||`
// short-circuit identically whether written inline or behind a predicate call.
//
// Only conditions that are provably self-contained are extracted. A condition
// qualifies when it is built exclusively from literals, parameter reads,
// comparisons, and boolean operators — no calls, no selectors, no literals with
// behaviour. That restriction is what makes the transform safe without type
// information: every name the predicate mentions is a parameter of the enclosing
// function, whose declared type is already recorded in the syntax tree, so the
// generated helper has correct parameter types by construction. Anything more
// exotic is refused and reported rather than guessed at, because a wrong rewrite
// that still compiles is the failure mode a security tool must never produce.
func reduceComplexity(code, lang string, limit int) passResult {
	var out passResult
	if lang != "go" || limit <= 0 {
		return out
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "generated.go", code, parser.ParseComments)
	if err != nil {
		return out
	}

	var repairs []Repair
	changed := false

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if complexityOf(fn.Body) <= limit {
			continue
		}

		extracted, refusal := extractPredicateHelper(fset, fn, file, limit)
		if refusal != "" {
			out.unrepairable = append(out.unrepairable, refusal)
		}
		if !extracted {
			continue
		}

		repairs = append(repairs, Repair{
			Kind: RepairComplexity,
			Rule: "HIGH_COMPLEXITY",
			Line: fset.Position(fn.Pos()).Line,
			Detail: fmt.Sprintf(
				"extracted a boolean predicate from %q to lower its cyclomatic complexity below the limit of %d",
				fn.Name.Name, limit),
		})
		changed = true
	}

	if !changed {
		return out
	}

	printed, err := printGoFile(fset, file)
	if err != nil {
		out.repairs = nil
		out.unrepairable = append(out.unrepairable,
			fmt.Sprintf("complexity reduction failed to render: %v (original code kept)", err))
		return out
	}

	if _, perr := parser.ParseFile(token.NewFileSet(), "generated.go", printed, parser.ParseComments); perr != nil {
		out.repairs = nil
		out.unrepairable = append(out.unrepairable,
			fmt.Sprintf("complexity reduction produced code that no longer parses (%v); original kept", perr))
		return out
	}

	out.code = printed
	out.repairs = repairs
	return out
}

// extractPredicateHelper rewrites one short-circuit condition of fn into a call
// to a new package-level predicate appended to file.
//
// Only a condition that is directly the Cond of an if-statement is considered.
// A nested sub-expression would have to be swapped inside its parent expression
// slot, which go/ast cannot do without parent pointers, so nested conditions are
// left for another round or for a human.
//
// It reports whether anything was extracted, plus a human-readable refusal when
// a candidate was rejected so the fix loop can surface the reason.
func extractPredicateHelper(fset *token.FileSet, fn *ast.FuncDecl, file *ast.File, limit int) (bool, string) {
	line := fset.Position(fn.Pos()).Line
	params := paramTypes(fn)
	if len(params) == 0 {
		return false, fmt.Sprintf(
			"HIGH_COMPLEXITY at line %d: %q declares no parameters, so its conditions cannot be "+
				"extracted into type-safe predicates; split it by hand", line, fn.Name.Name)
	}

	var candidates []*ast.IfStmt
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		stmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		if be, ok := stmt.Cond.(*ast.BinaryExpr); ok &&
			(be.Op == token.LAND || be.Op == token.LOR) {
			candidates = append(candidates, stmt)
		}
		return true
	})
	if len(candidates) == 0 {
		return false, fmt.Sprintf(
			"HIGH_COMPLEXITY at line %d: %q has no short-circuit boolean condition to extract; "+
				"reduce its branches by hand", line, fn.Name.Name)
	}

	var refusal string
	for _, stmt := range candidates {
		cond, _ := stmt.Cond.(*ast.BinaryExpr)

		names, safe := selfContainedIdents(cond)
		if !safe {
			if refusal == "" {
				refusal = fmt.Sprintf(
					"HIGH_COMPLEXITY at line %d: a condition in %q calls a function or reads a "+
						"non-parameter value, so extracting it would need type information the syntax "+
						"tree does not carry; refactor it by hand", line, fn.Name.Name)
			}
			continue
		}

		unknown := ""
		for _, name := range names {
			if _, ok := params[name]; !ok {
				unknown = name
				break
			}
		}
		if unknown != "" {
			if refusal == "" {
				refusal = fmt.Sprintf(
					"HIGH_COMPLEXITY at line %d: a condition in %q reads local %q; its type cannot be "+
						"inferred without a type checker, so it is left for a human",
					line, fn.Name.Name, unknown)
			}
			continue
		}

		// Build the helper around the original condition node. The node is
		// relocated rather than copied: it stops being the if-statement's Cond
		// below, so exactly one tree ends up referencing it.
		helperName := uniqueHelperName(file, fn.Name.Name)
		helper := &ast.FuncDecl{
			Name: ast.NewIdent(helperName),
			Type: &ast.FuncType{
				Params: &ast.FieldList{List: predicateParams(names, params)},
				Results: &ast.FieldList{
					List: []*ast.Field{{Type: ast.NewIdent("bool")}},
				},
			},
			Body: &ast.BlockStmt{
				List: []ast.Stmt{&ast.ReturnStmt{Results: []ast.Expr{cond}}},
			},
		}

		stmt.Cond = predicateCall(helperName, names, cond.Pos(), cond.End())
		file.Decls = append(file.Decls, helper)
		return true, ""
	}

	return false, refusal
}

// predicateParams builds the helper's parameter list, preserving the enclosing
// function's declared types so the helper type-checks identically.
func predicateParams(names []string, types map[string]ast.Expr) []*ast.Field {
	fields := make([]*ast.Field, 0, len(names))
	for _, name := range names {
		fields = append(fields, &ast.Field{
			Names: []*ast.Ident{ast.NewIdent(name)},
			Type:  types[name],
		})
	}
	return fields
}

// predicateCall builds `helper(a, b)` anchored on the source range it replaces,
// so the renderer keeps source ordering stable.
func predicateCall(name string, args []string, start, end token.Pos) *ast.CallExpr {
	exprs := make([]ast.Expr, 0, len(args))
	for _, arg := range args {
		ident := ast.NewIdent(arg)
		ident.NamePos = start
		exprs = append(exprs, ident)
	}
	return &ast.CallExpr{
		Fun:    &ast.Ident{NamePos: start, Name: name},
		Lparen: start,
		Rparen: end,
		Args:   exprs,
	}
}

// uniqueHelperName picks a predicate name that does not collide with an existing
// declaration, so repeated fix rounds converge instead of redefining symbols.
func uniqueHelperName(file *ast.File, base string) string {
	taken := map[string]bool{}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			taken[fn.Name.Name] = true
		}
	}
	for i := 1; ; i++ {
		candidate := fmt.Sprintf("%s_cond%d", base, i)
		if !taken[candidate] {
			return candidate
		}
	}
}

// selfContainedIdents returns the distinct identifiers a condition reads, and
// whether the condition is built only from constructs whose types and scopes are
// already known: literals, identifiers, unary and boolean operators, comparisons
// and parentheses.
//
// A call expression, selector, composite literal or function literal makes the
// condition unsafe, because any of those can depend on a local closure or a
// receiver that a new package-level predicate cannot reach.
func selfContainedIdents(expr ast.Expr) ([]string, bool) {
	var (
		names []string
		seen  = map[string]bool{}
		safe  = true
	)

	var walk func(ast.Expr)
	walk = func(e ast.Expr) {
		switch n := e.(type) {
		case nil:
			return
		case *ast.Ident:
			if n.Name == "_" || isGoKeyword(n.Name) {
				return
			}
			if !seen[n.Name] {
				seen[n.Name] = true
				names = append(names, n.Name)
			}
		case *ast.BasicLit:
		case *ast.BinaryExpr:
			walk(n.X)
			walk(n.Y)
		case *ast.ParenExpr:
			walk(n.X)
		case *ast.UnaryExpr:
			walk(n.X)
		default:
			safe = false
		}
	}
	walk(expr)

	return names, safe
}

// paramTypes maps each parameter name of a function to its declared type node.
func paramTypes(fn *ast.FuncDecl) map[string]ast.Expr {
	out := map[string]ast.Expr{}
	if fn.Type.Params == nil {
		return out
	}
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			out[name.Name] = field.Type
		}
	}
	return out
}

// complexityOf computes cyclomatic complexity using the same decision points and
// base value as the policy engine, so a reduction performed here is guaranteed to
// satisfy the rule that flagged the function.
func complexityOf(body *ast.BlockStmt) int {
	if body == nil {
		return 0
	}
	score := 1
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt:
			score++
		case *ast.ForStmt:
			score++
		case *ast.RangeStmt:
			score++
		case *ast.CaseClause:
			if len(node.List) > 0 {
				score++
			}
		case *ast.CommClause:
			if node.Comm != nil {
				score++
			}
		case *ast.BinaryExpr:
			if node.Op == token.LAND || node.Op == token.LOR {
				score++
			}
		case *ast.GoStmt:
			score++
		case *ast.DeferStmt:
			score++
		}
		return true
	})
	return score
}

func isGoKeyword(name string) bool {
	switch name {
	case "true", "false", "nil", "iota", "len", "cap", "new", "make",
		"append", "copy", "delete", "panic", "recover", "print", "println",
		"string", "int", "int8", "int16", "int32", "int64",
		"uint", "uint8", "uint16", "uint32", "uint64", "uintptr",
		"float32", "float64", "complex64", "complex128",
		"bool", "byte", "rune", "error", "any", "map", "chan", "func",
		"interface", "struct", "var", "const", "type", "range", "select":
		return true
	}
	return strings.EqualFold(name, "")
}