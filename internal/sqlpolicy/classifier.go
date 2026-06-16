// Package sqlpolicy classifies SQL statements before proxy forwarding.
package sqlpolicy

import "strings"

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

// Decision describes the SQL policy result and a stable generic reason.
type Decision struct {
	Kind   DecisionKind
	Reason string
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
		allowed[strings.ToLower(schema)] = struct{}{}
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
	if hasMultipleStatements(normalized) {
		return Decision{Kind: Reject, Reason: "multiple_statements"}
	}
	if strings.Contains(normalized, "/*!") {
		return Decision{Kind: Reject, Reason: "executable_comment"}
	}

	lower := strings.ToLower(normalized)
	if hasTrailingStatementTerminator(statement) {
		lower = trimStatementTerminator(lower)
	}
	switch {
	case c.allowDefaultSetup && isAllowedSetup(lower):
		return Decision{Kind: AllowSetup, Reason: "allowed_setup"}
	case strings.HasPrefix(lower, "use "):
		return c.classifyUse(lower)
	case isOperationalRead(lower):
		return Decision{Kind: AllowOperationalRead, Reason: "allowed_operational_read"}
	case !strings.HasPrefix(lower, "select "):
		return Decision{Kind: Reject, Reason: "unsupported_statement"}
	case containsAny(lower,
		" into outfile",
		" into dumpfile",
		" for update",
		" lock in share mode",
		" union ",
	) || referencesSystemSchema(lower):
		return Decision{Kind: Reject, Reason: "unsafe_read"}
	case hasUnapprovedFunctionCall(lower):
		return Decision{Kind: Reject, Reason: "routine_not_allowed"}
	default:
		return Decision{Kind: AllowRead, Reason: "read_only"}
	}
}

func (c *StaticClassifier) classifyUse(lower string) Decision {
	schema := strings.TrimSpace(strings.TrimPrefix(lower, "use "))
	schema = strings.Trim(schema, "`")
	if _, ok := c.allowedSchemas[schema]; ok {
		return Decision{Kind: AllowSetup, Reason: "allowed_schema"}
	}

	return Decision{Kind: Reject, Reason: "schema_not_allowed"}
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

func hasMultipleStatements(statement string) bool {
	trimmed := strings.TrimSpace(statement)
	withoutTrailing := strings.TrimSuffix(trimmed, ";")

	return strings.Contains(withoutTrailing, ";")
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

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}

	return false
}

func referencesSystemSchema(lower string) bool {
	for _, schema := range []string{"information_schema", "performance_schema", "mysql", "sys"} {
		for start := 0; ; {
			idx := strings.Index(lower[start:], schema)
			if idx < 0 {
				break
			}
			idx += start
			after := idx + len(schema)
			if isIdentifierBoundary(lower, idx-1) && schemaQualifierFollows(lower, after) {
				return true
			}
			start = after
		}
	}

	return false
}

func schemaQualifierFollows(lower string, index int) bool {
	for index < len(lower) && lower[index] == ' ' {
		index++
	}

	return index < len(lower) && lower[index] == '.'
}

func isIdentifierBoundary(value string, index int) bool {
	if index < 0 {
		return true
	}
	ch := value[index]

	return !isIdentifierByte(ch)
}

func isIdentifierByte(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_'
}

func isSpaceByte(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\f'
}

func hasUnapprovedFunctionCall(lower string) bool {
	remainder := lower
	for {
		idx := strings.Index(remainder, "(")
		if idx < 0 {
			return false
		}
		before := strings.TrimSpace(remainder[:idx])
		closeIdx := strings.IndexByte(remainder[idx+1:], ')')
		if closeIdx < 0 {
			return true
		}
		args := remainder[idx+1 : idx+1+closeIdx]
		if functionName(before) == "count" && isAllowedCountArgs(args) {
			remainder = remainder[idx+closeIdx+2:]
			continue
		}

		return true
	}
}

func isAllowedCountArgs(args string) bool {
	return strings.TrimSpace(args) == "*"
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

func functionName(beforeCall string) string {
	beforeCall = strings.TrimSpace(beforeCall)
	end := len(beforeCall)
	start := end
	for start > 0 {
		ch := beforeCall[start-1]
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' {
			start--
			continue
		}
		break
	}

	return beforeCall[start:end]
}
