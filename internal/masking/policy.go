// Package masking applies result-field allow rules and type-compatible masks.
package masking

import "strings"

// TypeFamily is the coarse MySQL value family used for M1 masking.
type TypeFamily string

const (
	// TypeText masks to a text placeholder.
	TypeText TypeFamily = "text"
	// TypeNumeric masks to zero.
	TypeNumeric TypeFamily = "numeric"
	// TypeDate masks to a MySQL zero-equivalent date.
	TypeDate TypeFamily = "date"
	// TypeTime masks to a MySQL zero-equivalent time.
	TypeTime TypeFamily = "time"
	// TypeTimestamp masks to a MySQL zero-equivalent timestamp.
	TypeTimestamp TypeFamily = "timestamp"
	// TypeBinary masks to empty bytes.
	TypeBinary TypeFamily = "binary"
)

// Field contains physical origin metadata for one result field.
type Field struct {
	Schema         string
	OriginalTable  string
	OriginalColumn string
	TypeFamily     TypeFamily
}

// Value is one text-protocol result value.
type Value struct {
	Raw  []byte
	Null bool
}

// TableRule allows either all columns or selected columns from a physical
// schema/table origin.
type TableRule struct {
	Schema          string   `toml:"schema"`
	Table           string   `toml:"table"`
	AllowAllColumns bool     `toml:"allow_all_columns"`
	Columns         []string `toml:"columns"`
}

// Config contains M1 global masking allow rules.
type Config struct {
	TableRules       []TableRule     `toml:"-"`
	GlobalColumns    []string        `toml:"-"`
	AllowTables      []TableRule     `toml:"allow_tables"`
	AllowColumns     []TableRule     `toml:"allow_columns"`
	AllowColumnNames ColumnNameRules `toml:"allow_column_names"`
}

// ColumnNameRules allows selected columns by global physical column name.
type ColumnNameRules struct {
	Names []string `toml:"names"`
}

// Policy decides whether to pass result values through or return masks.
type Policy interface {
	Mask(field Field, value Value) Value
}

// StaticPolicy is the built-in M1 masking policy.
type StaticPolicy struct {
	tableAll      map[string]struct{}
	tableColumns  map[string]map[string]struct{}
	globalColumns map[string]struct{}
}

// NewPolicy creates a global M1 masking policy.
func NewPolicy(config Config) *StaticPolicy {
	policy := &StaticPolicy{
		tableAll:      make(map[string]struct{}),
		tableColumns:  make(map[string]map[string]struct{}),
		globalColumns: make(map[string]struct{}),
	}

	for _, rule := range config.TableRules {
		policy.addTableRule(rule)
	}
	for _, rule := range config.AllowTables {
		rule.AllowAllColumns = true
		policy.addTableRule(rule)
	}
	for _, rule := range config.AllowColumns {
		policy.addTableRule(rule)
	}

	for _, column := range config.GlobalColumns {
		policy.globalColumns[strings.ToLower(column)] = struct{}{}
	}
	for _, column := range config.AllowColumnNames.Names {
		policy.globalColumns[strings.ToLower(column)] = struct{}{}
	}

	return policy
}

// Mask returns the original value when an origin rule allows it; otherwise it
// returns a type-family-compatible placeholder. NULL values are preserved.
func (p *StaticPolicy) Mask(field Field, value Value) Value {
	if value.Null {
		return Value{Null: true}
	}
	if p.allowed(field) {
		return value
	}

	switch field.TypeFamily {
	case TypeNumeric:
		return Value{Raw: []byte("0")}
	case TypeDate:
		return Value{Raw: []byte("0000-00-00")}
	case TypeTime:
		return Value{Raw: []byte("00:00:00")}
	case TypeTimestamp:
		return Value{Raw: []byte("0000-00-00 00:00:00")}
	case TypeBinary:
		return Value{Raw: []byte{}}
	default:
		return Value{Raw: []byte("***MASKED***")}
	}
}

func (p *StaticPolicy) allowed(field Field) bool {
	if field.Schema == "" || field.OriginalTable == "" || field.OriginalColumn == "" {
		return false
	}

	key := originKey(field.Schema, field.OriginalTable)
	if _, ok := p.tableAll[key]; ok {
		return true
	}
	if columns := p.tableColumns[key]; columns != nil {
		if _, ok := columns[strings.ToLower(field.OriginalColumn)]; ok {
			return true
		}
	}
	if _, ok := p.globalColumns[strings.ToLower(field.OriginalColumn)]; ok {
		return true
	}

	return false
}

func (p *StaticPolicy) addTableRule(rule TableRule) {
	key := originKey(rule.Schema, rule.Table)
	if rule.AllowAllColumns {
		p.tableAll[key] = struct{}{}
	}
	if len(rule.Columns) == 0 {
		return
	}

	columns := p.tableColumns[key]
	if columns == nil {
		columns = make(map[string]struct{}, len(rule.Columns))
		p.tableColumns[key] = columns
	}
	for _, column := range rule.Columns {
		columns[strings.ToLower(column)] = struct{}{}
	}
}

func originKey(schema string, table string) string {
	return strings.ToLower(schema) + "." + strings.ToLower(table)
}
