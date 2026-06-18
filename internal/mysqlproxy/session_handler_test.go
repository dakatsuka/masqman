package mysqlproxy

import (
	"testing"

	"github.com/dakatsuka/masqman/internal/masking"

	"github.com/go-mysql-org/go-mysql/mysql"
)

func TestSessionHandlerAppliesPolicyBeforeForwarding(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{result: &mysql.Result{}}
	handler := newSessionHandler(testPolicyConfig(), upstream)

	result, err := handler.HandleQuery("select id from employees")
	if err != nil {
		t.Fatalf("HandleQuery(allowed) error = %v, want nil", err)
	}
	if result != upstream.result {
		t.Fatal("HandleQuery(allowed) did not return upstream result")
	}
	if upstream.query != "select id from employees" {
		t.Fatalf("upstream query = %q, want allowed query", upstream.query)
	}

	_, err = handler.HandleQuery("drop table employees")
	assertMySQLErrorCode(t, err, mysql.ER_SPECIFIC_ACCESS_DENIED_ERROR)
	if upstream.query != "select id from employees" {
		t.Fatalf("upstream query after rejection = %q, want unchanged allowed query", upstream.query)
	}
}

func TestSessionHandlerAppliesSchemaPolicyBeforeInitDB(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{}
	handler := newSessionHandler(testPolicyConfig(), upstream)

	if err := handler.UseDB("app"); err != nil {
		t.Fatalf("UseDB(allowed) error = %v, want nil", err)
	}
	if upstream.database != "app" {
		t.Fatalf("upstream database = %q, want app", upstream.database)
	}

	err := handler.UseDB("mysql")
	assertMySQLErrorCode(t, err, mysql.ER_SPECIFIC_ACCESS_DENIED_ERROR)
	if upstream.database != "app" {
		t.Fatalf("upstream database after rejection = %q, want unchanged app", upstream.database)
	}
}

func TestSessionHandlerPassesSafeExpressionResultsThroughMasking(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{
		result: resultWithTextRows(
			[]*mysql.Field{{Name: []byte("count(*)"), Type: mysql.MYSQL_TYPE_LONGLONG}},
			[][]*string{{stringPtr("42")}},
		),
	}
	handler := newSessionHandlerWithMasking(testPolicyConfig(), masking.NewPolicy(masking.Config{}), upstream)

	result, err := handler.HandleQuery("select count(*) from employees")
	if err != nil {
		t.Fatalf("HandleQuery() error = %v, want nil", err)
	}

	values, err := result.RowDatas[0].Parse(result.Fields, false, nil)
	if err != nil {
		t.Fatalf("parse masked row: %v", err)
	}
	if got := fieldValueText(t, values[0]); got != "42" {
		t.Fatalf("masked COUNT(*) = %q, want 42", got)
	}
}

func TestSessionHandlerPassesOriginFreeOperationalLiteralThroughMasking(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{
		result: resultWithTextRows(
			[]*mysql.Field{{Name: []byte("1"), Type: mysql.MYSQL_TYPE_LONG}},
			[][]*string{{stringPtr("1")}},
		),
	}
	handler := newSessionHandlerWithMasking(testPolicyConfig(), masking.NewPolicy(masking.Config{}), upstream)

	result, err := handler.HandleQuery("select 1")
	if err != nil {
		t.Fatalf("HandleQuery() error = %v, want nil", err)
	}

	values, err := result.RowDatas[0].Parse(result.Fields, false, nil)
	if err != nil {
		t.Fatalf("parse masked row: %v", err)
	}
	if got := fieldValueText(t, values[0]); got != "1" {
		t.Fatalf("masked origin-free SELECT 1 = %q, want 1", got)
	}
}

func TestSessionHandlerRejectsOversizedQueryBeforeForwarding(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{}
	handler := newSessionHandlerWithLimits(
		testPolicyConfig(),
		nil,
		resourceLimits{maxQueryBytes: len("select 1")},
		upstream,
	)

	_, err := handler.HandleQuery("select 12")
	assertMySQLErrorCode(t, err, mysql.ER_NET_PACKET_TOO_LARGE)
	if upstream.executeCalls != 0 {
		t.Fatalf("upstream Execute calls = %d, want 0", upstream.executeCalls)
	}
}

func TestSessionHandlerAllowsQueryAtMaxQueryBytesBoundary(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{result: &mysql.Result{}}
	handler := newSessionHandlerWithLimits(
		testPolicyConfig(),
		nil,
		resourceLimits{maxQueryBytes: len("select 1")},
		upstream,
	)

	_, err := handler.HandleQuery("select 1")
	if err != nil {
		t.Fatalf("HandleQuery() error = %v, want nil", err)
	}
	if upstream.executeCalls != 1 {
		t.Fatalf("upstream Execute calls = %d, want 1", upstream.executeCalls)
	}
}

func TestSessionHandlerRejectsOversizedUnsafeQueryBeforePolicy(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{}
	handler := newSessionHandlerWithLimits(
		testPolicyConfig(),
		nil,
		resourceLimits{maxQueryBytes: len("drop table")},
		upstream,
	)

	_, err := handler.HandleQuery("drop table employees")
	assertMySQLErrorCode(t, err, mysql.ER_NET_PACKET_TOO_LARGE)
	if upstream.executeCalls != 0 {
		t.Fatalf("upstream Execute calls = %d, want 0", upstream.executeCalls)
	}
}

func TestSessionHandlerSynthesizesMaxAllowedPacketFromQueryLimit(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{
		result: resultWithTextRows(
			[]*mysql.Field{{Name: []byte("@@max_allowed_packet"), Type: mysql.MYSQL_TYPE_LONGLONG}},
			[][]*string{{stringPtr("67108864")}},
		),
	}
	handler := newSessionHandlerWithLimits(
		testPolicyConfig(),
		nil,
		resourceLimits{maxQueryBytes: 1024},
		upstream,
	)

	result, err := handler.HandleQuery("select @@max_allowed_packet")
	if err != nil {
		t.Fatalf("HandleQuery() error = %v, want nil", err)
	}
	if upstream.executeCalls != 0 {
		t.Fatalf("upstream Execute calls = %d, want 0", upstream.executeCalls)
	}

	values, err := result.RowDatas[0].Parse(result.Fields, false, nil)
	if err != nil {
		t.Fatalf("parse synthesized row: %v", err)
	}
	if got := fieldValueText(t, values[0]); got != "1024" {
		t.Fatalf("@@max_allowed_packet = %q, want 1024", got)
	}
}

func TestSessionHandlerRejectsSetupStatementsThatReturnResultsets(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{
		result: resultWithTextRows(
			[]*mysql.Field{{Name: []byte("leaked"), Type: mysql.MYSQL_TYPE_VAR_STRING}},
			[][]*string{{stringPtr("secret")}},
		),
	}
	handler := newSessionHandlerWithMasking(testPolicyConfig(), masking.NewPolicy(masking.Config{}), upstream)

	result, err := handler.HandleQuery("set names utf8mb4")
	if result != nil {
		t.Fatalf("HandleQuery() result = %#v, want nil", result)
	}
	assertUnsupported(t, err)
	if !upstream.closed {
		t.Fatal("upstream was not closed after setup statement returned a resultset")
	}
}

func TestSessionHandlerMasksOperationalReadWithPhysicalOriginMetadata(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{
		result: resultWithTextRows(
			[]*mysql.Field{{
				Schema:   []byte("app"),
				Name:     []byte("1"),
				OrgTable: []byte("employees"),
				OrgName:  []byte("salary"),
				Type:     mysql.MYSQL_TYPE_LONG,
			}},
			[][]*string{{stringPtr("90000")}},
		),
	}
	handler := newSessionHandlerWithMasking(testPolicyConfig(), masking.NewPolicy(masking.Config{}), upstream)

	result, err := handler.HandleQuery("select 1")
	if err != nil {
		t.Fatalf("HandleQuery() error = %v, want nil", err)
	}

	values, err := result.RowDatas[0].Parse(result.Fields, false, nil)
	if err != nil {
		t.Fatalf("parse masked row: %v", err)
	}
	if got := fieldValueText(t, values[0]); got != "0" {
		t.Fatalf("operational read with physical origin = %q, want numeric mask", got)
	}
}
