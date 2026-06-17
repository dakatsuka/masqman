// Package sqlpolicy classifies SQL statements before proxy forwarding.
package sqlpolicy

import (
	"strings"

	"github.com/pingcap/tidb/pkg/parser"
	"github.com/pingcap/tidb/pkg/parser/ast"

	// Register TiDB's parser value-expression driver.
	_ "github.com/pingcap/tidb/pkg/parser/test_driver"
)

// DecisionKind is the proxy action selected for one text-protocol statement.
type DecisionKind string

const (
	// AllowRead forwards a user-data read query to the upstream database.
	AllowRead DecisionKind = "allow_read"
	// AllowOperationalRead forwards a built-in origin-free startup probe.
	AllowOperationalRead DecisionKind = "allow_operational_read"
	// AllowSetup forwards a harmless no-result setup statement.
	AllowSetup DecisionKind = "allow_setup"
	// Reject blocks a statement before upstream forwarding.
	Reject DecisionKind = "reject"
)

// ExpressionKind identifies the safe expression facts derived from a SELECT list.
type ExpressionKind string

const (
	// ExpressionUnknown means the classifier could not prove a narrower expression fact.
	ExpressionUnknown ExpressionKind = "unknown"
	// ExpressionColumn means the result expression is a column reference.
	ExpressionColumn ExpressionKind = "column"
	// ExpressionLiteral means the result expression is an origin-free literal.
	ExpressionLiteral ExpressionKind = "literal"
	// ExpressionSafeBuiltin means the expression is an allowed origin-free builtin probe.
	ExpressionSafeBuiltin ExpressionKind = "safe_builtin"
	// ExpressionCountStar means the expression is exactly COUNT(*).
	ExpressionCountStar ExpressionKind = "count_star"
)

// Decision describes the SQL policy result and a stable generic reason.
type Decision struct {
	Kind              DecisionKind
	Reason            string
	ExpressionContext []ExpressionContext
}

// ExpressionContext describes a parsed SELECT-list expression fact that result
// masking can combine with returned MySQL column metadata. Consumers must
// branch on Kind first; SafeBuiltin only annotates built-in or aggregate
// expression kinds that are explicitly safe to pass through.
type ExpressionContext struct {
	Kind         ExpressionKind
	FunctionName string
	SafeBuiltin  bool
}

// Classifier decides whether a text SQL statement is safe for M1 forwarding.
type Classifier interface {
	Classify(statement string) Decision
}

// Config controls the conservative M1 statement classifier.
type Config struct {
	AllowedSchemas    []string
	AllowDefaultSetup bool
}

// StaticClassifier is the built-in M1 SQL policy.
type StaticClassifier struct {
	allowedSchemas    map[string]struct{}
	allowDefaultSetup bool
}

// NewClassifier creates the built-in conservative SQL classifier.
func NewClassifier(config Config) *StaticClassifier {
	allowed := make(map[string]struct{}, len(config.AllowedSchemas))
	for _, schema := range config.AllowedSchemas {
		allowed[schema] = struct{}{}
	}

	return &StaticClassifier{
		allowedSchemas:    allowed,
		allowDefaultSetup: config.AllowDefaultSetup,
	}
}

// Classify returns the M1 forwarding decision for a single SQL statement.
func (c *StaticClassifier) Classify(statement string) Decision {
	normalized := normalize(statement)
	if normalized == "" {
		return Decision{Kind: Reject, Reason: "empty_statement"}
	}
	if strings.Contains(normalized, "/*!") {
		return Decision{Kind: Reject, Reason: "executable_comment"}
	}

	lower := strings.ToLower(normalized)
	if hasTrailingStatementTerminator(statement) {
		lower = trimStatementTerminator(lower)
	}

	parsed, _, err := parser.New().ParseSQL(statement)
	if err != nil {
		return Decision{Kind: Reject, Reason: "parse_error"}
	}
	if len(parsed) != 1 {
		return Decision{Kind: Reject, Reason: "multiple_statements"}
	}

	switch stmt := parsed[0].(type) {
	case *ast.SetStmt:
		return c.classifySet(stmt, lower)
	case *ast.UseStmt:
		return c.classifyUseName(stmt.DBName)
	case *ast.SelectStmt:
		return c.classifySelect(stmt, lower, statement)
	default:
		return Decision{Kind: Reject, Reason: "unsupported_statement"}
	}
}

func (c *StaticClassifier) classifySelect(stmt *ast.SelectStmt, lower string, source string) Decision {
	contexts := expressionContexts(stmt, source)
	if isOperationalRead(lower) {
		return Decision{
			Kind:              AllowOperationalRead,
			Reason:            "allowed_operational_read",
			ExpressionContext: contexts,
		}
	}
	if stmt.Kind != ast.SelectStmtKindSelect {
		return Decision{Kind: Reject, Reason: "unsupported_statement"}
	}

	safety := &selectSafetyVisitor{source: source}
	stmt.Accept(safety) //nolint:errcheck // The visitor records fail-closed policy state.
	switch {
	case safety.unsafeRead:
		return Decision{Kind: Reject, Reason: "unsafe_read"}
	case safety.disallowedFunction:
		return Decision{Kind: Reject, Reason: "routine_not_allowed"}
	default:
		return Decision{Kind: AllowRead, Reason: "read_only", ExpressionContext: contexts}
	}
}

func (c *StaticClassifier) classifySet(_ *ast.SetStmt, lower string) Decision {
	if c.allowDefaultSetup && isAllowedSetup(lower) {
		return Decision{Kind: AllowSetup, Reason: "allowed_setup"}
	}

	return Decision{Kind: Reject, Reason: "unsupported_statement"}
}

func (c *StaticClassifier) classifyUseName(schema string) Decision {
	schema = strings.TrimSpace(schema)
	if _, ok := c.allowedSchemas[schema]; ok {
		return Decision{Kind: AllowSetup, Reason: "allowed_schema"}
	}

	return Decision{Kind: Reject, Reason: "schema_not_allowed"}
}

type selectSafetyVisitor struct {
	source             string
	unsafeRead         bool
	disallowedFunction bool
}

func (visitor *selectSafetyVisitor) Enter(node ast.Node) (ast.Node, bool) {
	switch current := node.(type) {
	case *ast.SelectStmt:
		if current.SelectIntoOpt != nil || hasSelectLock(current) {
			visitor.unsafeRead = true
		}
	case *ast.TableName:
		if isSystemSchema(current.Schema.L) {
			visitor.unsafeRead = true
		}
	case *ast.ColumnName:
		if isSystemSchema(current.Schema.L) {
			visitor.unsafeRead = true
		}
	case *ast.FuncCallExpr:
		visitor.disallowedFunction = true

		return node, true
	case *ast.AggregateFuncExpr:
		if !isAllowedCountAggregate(current, visitor.source) {
			visitor.disallowedFunction = true
		}

		return node, true
	case *ast.WindowFuncExpr:
		visitor.disallowedFunction = true

		return node, true
	}

	return node, false
}

func (visitor *selectSafetyVisitor) Leave(node ast.Node) (ast.Node, bool) {
	return node, true
}

func hasSelectLock(stmt *ast.SelectStmt) bool {
	return stmt.LockInfo != nil && stmt.LockInfo.LockType != ast.SelectLockNone
}

func isSystemSchema(schema string) bool {
	switch strings.ToLower(schema) {
	case "information_schema", "performance_schema", "mysql", "sys":
		return true
	default:
		return false
	}
}

func isAllowedCountAggregate(expr *ast.AggregateFuncExpr, source string) bool {
	if !strings.EqualFold(expr.F, ast.AggFuncCount) || expr.Distinct {
		return false
	}

	return compactSQLCallAt(source, expr.OriginTextPosition()) == "count(*)"
}

func expressionContexts(stmt *ast.SelectStmt, source string) []ExpressionContext {
	if stmt.Fields == nil || len(stmt.Fields.Fields) == 0 {
		return nil
	}

	contexts := make([]ExpressionContext, 0, len(stmt.Fields.Fields))
	for _, field := range stmt.Fields.Fields {
		if field.WildCard != nil {
			return nil
		}
		contexts = append(contexts, expressionContext(field.Expr, source))
	}

	return contexts
}

func expressionContext(expr ast.ExprNode, source string) ExpressionContext {
	switch current := expr.(type) {
	case *ast.ColumnNameExpr:
		return ExpressionContext{Kind: ExpressionColumn}
	case ast.ValueExpr:
		return ExpressionContext{Kind: ExpressionLiteral}
	case *ast.FuncCallExpr:
		if isSafeBuiltinFunction(current.FnName.L) && len(current.Args) == 0 && current.Schema.L == "" {
			return ExpressionContext{
				Kind:         ExpressionSafeBuiltin,
				FunctionName: current.FnName.L,
				SafeBuiltin:  true,
			}
		}
	case *ast.VariableExpr:
		if current.IsSystem && !current.ExplicitScope && isOperationalVariable(current.Name) {
			return ExpressionContext{
				Kind:         ExpressionSafeBuiltin,
				FunctionName: "@@" + strings.ToLower(current.Name),
				SafeBuiltin:  true,
			}
		}
	case *ast.AggregateFuncExpr:
		if isAllowedCountAggregate(current, source) {
			return ExpressionContext{
				Kind:         ExpressionCountStar,
				FunctionName: ast.AggFuncCount,
				SafeBuiltin:  true,
			}
		}
	}

	return ExpressionContext{Kind: ExpressionUnknown}
}

func isSafeBuiltinFunction(name string) bool {
	switch strings.ToLower(name) {
	case "now", "database":
		return true
	default:
		return false
	}
}

func isOperationalVariable(name string) bool {
	switch strings.ToLower(name) {
	case "version",
		"version_comment",
		"max_allowed_packet",
		"character_set_client",
		"character_set_connection",
		"character_set_results",
		"collation_connection":
		return true
	default:
		return false
	}
}

func compactSQLCallAt(source string, offset int) string {
	if offset < 0 || offset >= len(source) {
		return ""
	}
	end := callEndAt(source, offset)
	if end < 0 {
		return ""
	}

	return compactSQLSyntax(source[offset:end])
}

func callEndAt(source string, offset int) int {
	depth := 0
	for idx := offset; idx < len(source); {
		switch {
		case source[idx] == '\'' || source[idx] == '"':
			idx = skipQuotedString(source, idx)
		case source[idx] == '`':
			idx = skipQuotedIdentifier(source, idx)
		case isDashDashComment(source, idx):
			idx = skipLineComment(source, idx+2)
		case source[idx] == '#':
			idx = skipLineComment(source, idx+1)
		case source[idx] == '/' && idx+1 < len(source) && source[idx+1] == '*' &&
			!isVersionedComment(source, idx):
			idx = skipBlockComment(source, idx+2)
		case source[idx] == '(':
			depth++
			idx++
		case source[idx] == ')':
			if depth == 0 {
				return -1
			}
			depth--
			idx++
			if depth == 0 {
				return idx
			}
		default:
			idx++
		}
	}

	return -1
}

func compactSQLSyntax(source string) string {
	var out strings.Builder
	for idx := 0; idx < len(source); {
		switch {
		case isSpaceByte(source[idx]):
			idx++
		case isDashDashComment(source, idx):
			idx = skipLineComment(source, idx+2)
		case source[idx] == '#':
			idx = skipLineComment(source, idx+1)
		case source[idx] == '/' && idx+1 < len(source) && source[idx+1] == '*' &&
			!isVersionedComment(source, idx):
			idx = skipBlockComment(source, idx+2)
		default:
			out.WriteByte(toLowerASCII(source[idx]))
			idx++
		}
	}

	return out.String()
}

func skipQuotedString(source string, index int) int {
	quote := source[index]
	index++
	for index < len(source) {
		if source[index] == '\\' && index+1 < len(source) {
			index += 2
			continue
		}
		if source[index] == quote {
			index++
			if index < len(source) && source[index] == quote {
				index++
				continue
			}

			return index
		}
		index++
	}

	return len(source)
}

func skipQuotedIdentifier(source string, index int) int {
	index++
	for index < len(source) {
		if source[index] == '`' {
			index++
			if index < len(source) && source[index] == '`' {
				index++
				continue
			}

			return index
		}
		index++
	}

	return len(source)
}

func skipLineComment(source string, index int) int {
	for index < len(source) && source[index] != '\n' {
		index++
	}

	return index
}

func skipBlockComment(source string, index int) int {
	for index+1 < len(source) && !isBlockCommentEnd(source, index) {
		index++
	}
	if index+1 < len(source) {
		return index + 2
	}

	return len(source)
}

func toLowerASCII(ch byte) byte {
	if ch >= 'A' && ch <= 'Z' {
		return ch + ('a' - 'A')
	}

	return ch
}

func normalize(statement string) string {
	return strings.Join(strings.Fields(scanSQL(statement)), " ")
}

func trimStatementTerminator(statement string) string {
	statement = strings.TrimSpace(statement)
	statement = strings.TrimSuffix(statement, ";")

	return strings.TrimSpace(statement)
}

func hasTrailingStatementTerminator(statement string) bool {
	var last byte
	for i := 0; i < len(statement); {
		switch {
		case statement[i] == '\'' || statement[i] == '"':
			last = '?'
			quote := statement[i]
			i++
			for i < len(statement) {
				if statement[i] == '\\' && i+1 < len(statement) {
					i += 2
					continue
				}
				if statement[i] == quote {
					i++
					break
				}
				i++
			}
		case statement[i] == '`':
			last = '`'
			i++
			for i < len(statement) {
				if statement[i] == '`' {
					i++
					break
				}
				i++
			}
		case isDashDashComment(statement, i):
			i += 2
			for i < len(statement) && statement[i] != '\n' {
				i++
			}
		case statement[i] == '#':
			i++
			for i < len(statement) && statement[i] != '\n' {
				i++
			}
		case statement[i] == '/' && i+1 < len(statement) && statement[i+1] == '*' &&
			!isVersionedComment(statement, i):
			i += 2
			for i+1 < len(statement) && !isBlockCommentEnd(statement, i) {
				i++
			}
			if i+1 < len(statement) {
				i += 2
			}
		default:
			if !isSpaceByte(statement[i]) {
				last = statement[i]
			}
			i++
		}
	}

	return last == ';'
}

func scanSQL(statement string) string {
	var out strings.Builder

	for i := 0; i < len(statement); {
		switch {
		case statement[i] == '\'' || statement[i] == '"':
			out.WriteByte('?')
			quote := statement[i]
			i++
			for i < len(statement) {
				if statement[i] == '\\' && i+1 < len(statement) {
					i += 2
					continue
				}
				if statement[i] == quote {
					i++
					break
				}
				i++
			}
		case statement[i] == '`':
			i++
			for i < len(statement) {
				if statement[i] == '`' {
					i++
					break
				}
				out.WriteByte(statement[i])
				i++
			}
		case isDashDashComment(statement, i):
			out.WriteByte(' ')
			i += 2
			for i < len(statement) && statement[i] != '\n' {
				i++
			}
		case statement[i] == '#':
			out.WriteByte(' ')
			i++
			for i < len(statement) && statement[i] != '\n' {
				i++
			}
		case statement[i] == '/' && i+1 < len(statement) && statement[i+1] == '*' &&
			!isVersionedComment(statement, i):
			out.WriteByte(' ')
			i += 2
			for i+1 < len(statement) && !isBlockCommentEnd(statement, i) {
				i++
			}
			if i+1 < len(statement) {
				i += 2
			}
		default:
			out.WriteByte(statement[i])
			i++
		}
	}

	return out.String()
}

func isOperationalRead(lower string) bool {
	probe := strings.TrimSuffix(lower, ";")
	probe = strings.TrimSuffix(probe, " limit 1")
	switch probe {
	case "select 1",
		"select now()",
		"select database()",
		"select @@version",
		"select @@version_comment",
		"select @@max_allowed_packet",
		"select @@character_set_client",
		"select @@character_set_connection",
		"select @@character_set_results",
		"select @@collation_connection":
		return true
	default:
		return false
	}
}

func isAllowedSetup(lower string) bool {
	if strings.Contains(lower, ",") {
		return false
	}
	if strings.HasPrefix(lower, "set names ") {
		value := strings.TrimSpace(strings.TrimPrefix(lower, "set names "))
		return isSimpleCharsetValue(value)
	}
	const assignment = "set character_set_results"
	if strings.HasPrefix(lower, assignment) {
		value := strings.TrimSpace(strings.TrimPrefix(lower, assignment))
		value = strings.TrimSpace(strings.TrimPrefix(value, "="))

		return isSimpleCharsetValue(value) || value == "null" || value == "default"
	}

	return false
}

func isSimpleCharsetValue(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' {
			continue
		}

		return false
	}

	return true
}

func isSpaceByte(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\f'
}

func isBlockCommentEnd(statement string, index int) bool {
	return statement[index] == '*' && statement[index+1] == '/'
}

func isDashDashComment(statement string, index int) bool {
	if statement[index] != '-' || index+1 >= len(statement) || statement[index+1] != '-' {
		return false
	}
	if index+2 >= len(statement) {
		return false
	}

	next := statement[index+2]

	return next == ' ' || next == '\t' || next == '\n' || next == '\r' || next == '\f'
}

func isVersionedComment(statement string, index int) bool {
	return index+2 < len(statement) && statement[index] == '/' &&
		statement[index+1] == '*' && statement[index+2] == '!'
}
