package masking_test

import (
	"testing"

	"github.com/dakatsuka/masqman/internal/masking"
)

func TestPolicyAllowsPhysicalOriginRules(t *testing.T) {
	t.Parallel()

	policy := masking.NewPolicy(masking.Config{
		TableRules: []masking.TableRule{
			{Schema: "app", Table: "departments", AllowAllColumns: true},
			{Schema: "app", Table: "employees", Columns: []string{"id", "name"}},
		},
		GlobalColumns: []string{"created_at"},
	})

	for _, field := range []masking.Field{
		{Schema: "app", OriginalTable: "departments", OriginalColumn: "secret", TypeFamily: masking.TypeText},
		{Schema: "app", OriginalTable: "employees", OriginalColumn: "name", TypeFamily: masking.TypeText},
		{Schema: "app", OriginalTable: "employees", OriginalColumn: "created_at", TypeFamily: masking.TypeTimestamp},
	} {
		got := policy.Mask(field, masking.Value{Raw: []byte("visible")})
		if string(got.Raw) != "visible" || got.Null {
			t.Fatalf("Mask(%#v) = %#v, want visible", field, got)
		}
	}
}

func TestPolicyMasksUnknownAndDisallowedFieldsByType(t *testing.T) {
	t.Parallel()

	policy := masking.NewPolicy(masking.Config{
		TableRules: []masking.TableRule{{Schema: "app", Table: "employees", Columns: []string{"id"}}},
	})

	tests := []struct {
		name  string
		field masking.Field
		want  string
	}{
		{
			name:  "disallowed text",
			field: masking.Field{Schema: "app", OriginalTable: "employees", OriginalColumn: "email", TypeFamily: masking.TypeText},
			want:  "***MASKED***",
		},
		{
			name:  "unknown numeric expression",
			field: masking.Field{TypeFamily: masking.TypeNumeric},
			want:  "0",
		},
		{
			name:  "unknown timestamp",
			field: masking.Field{TypeFamily: masking.TypeTimestamp},
			want:  "0000-00-00 00:00:00",
		},
		{
			name:  "unknown date",
			field: masking.Field{TypeFamily: masking.TypeDate},
			want:  "0000-00-00",
		},
		{
			name:  "unknown time",
			field: masking.Field{TypeFamily: masking.TypeTime},
			want:  "00:00:00",
		},
		{
			name:  "unknown binary",
			field: masking.Field{TypeFamily: masking.TypeBinary},
			want:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := policy.Mask(tc.field, masking.Value{Raw: []byte("secret")})
			if string(got.Raw) != tc.want || got.Null {
				t.Fatalf("Mask() = %#v, want raw %q", got, tc.want)
			}
		})
	}
}

func TestPolicyPreservesNullValues(t *testing.T) {
	t.Parallel()

	policy := masking.NewPolicy(masking.Config{})
	got := policy.Mask(masking.Field{TypeFamily: masking.TypeText}, masking.Value{Null: true})
	if !got.Null || got.Raw != nil {
		t.Fatalf("Mask(NULL) = %#v, want NULL preserved", got)
	}
}
