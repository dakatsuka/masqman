package mysqlproxy

import (
	"context"
	"errors"
	"testing"

	"github.com/dakatsuka/masqman/internal/audit"
	"github.com/dakatsuka/masqman/internal/masking"

	"github.com/go-mysql-org/go-mysql/client"
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

func TestSessionHandlerAuditsAllowedMaskedQuery(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{
		result: resultWithTextRows(
			[]*mysql.Field{
				{
					Schema:   []byte("app"),
					Name:     []byte("id"),
					OrgTable: []byte("employees"),
					OrgName:  []byte("id"),
					Type:     mysql.MYSQL_TYPE_LONG,
				},
				{
					Schema:   []byte("app"),
					Name:     []byte("email"),
					OrgTable: []byte("employees"),
					OrgName:  []byte("email"),
					Type:     mysql.MYSQL_TYPE_VAR_STRING,
				},
			},
			[][]*string{{stringPtr("1"), stringPtr("alice@example.test")}},
		),
	}
	logger := &recordingAuditLogger{}
	query := "select id, email from employees where id = 1"
	handler := newSessionHandlerWithAudit(
		testPolicyConfig(),
		masking.NewPolicy(masking.Config{
			TableRules: []masking.TableRule{{Schema: "app", Table: "employees", Columns: []string{"id"}}},
		}),
		resourceLimits{},
		upstream,
		logger,
		auditIdentity{userID: "alice", sourceAddr: "10.0.0.1"},
	)

	_, err := handler.HandleQuery(query)
	if err != nil {
		t.Fatalf("HandleQuery() error = %v, want nil", err)
	}

	event := logger.singleEvent(t)
	if event.Kind != audit.EventQuery ||
		event.UserID != "alice" ||
		event.SourceAddr != "10.0.0.1" ||
		event.NormalizedStatement != audit.NormalizeStatement(query) ||
		event.Decision != "allow_read" ||
		event.MaskedFields != 1 ||
		event.ErrorClass != "" {
		t.Fatalf("audit event = %#v", event)
	}
}

func TestSessionHandlerAuditsPolicyRejectionBeforeForwarding(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{}
	logger := &recordingAuditLogger{}
	query := "drop table employees"
	handler := newSessionHandlerWithAudit(
		testPolicyConfig(),
		nil,
		resourceLimits{},
		upstream,
		logger,
		auditIdentity{userID: "alice", sourceAddr: "10.0.0.1"},
	)

	_, err := handler.HandleQuery(query)
	assertMySQLErrorCode(t, err, mysql.ER_SPECIFIC_ACCESS_DENIED_ERROR)
	if upstream.executeCalls != 0 {
		t.Fatalf("upstream Execute calls = %d, want 0", upstream.executeCalls)
	}

	event := logger.singleEvent(t)
	if event.Kind != audit.EventQuery ||
		event.Decision != "reject" ||
		event.NormalizedStatement != audit.NormalizeStatement(query) ||
		event.ErrorClass != "policy_reject" {
		t.Fatalf("audit event = %#v", event)
	}
}

func TestSessionHandlerFailsClosedWhenQueryAuditFails(t *testing.T) {
	t.Parallel()

	auditErr := errors.New("audit sink unavailable")
	upstream := &recordingUpstream{result: &mysql.Result{}}
	logger := &recordingAuditLogger{err: auditErr}
	handler := newSessionHandlerWithAudit(
		testPolicyConfig(),
		nil,
		resourceLimits{},
		upstream,
		logger,
		auditIdentity{userID: "alice", sourceAddr: "10.0.0.1"},
	)

	_, err := handler.HandleQuery("select id from employees")
	assertUnsupported(t, err)
	if !upstream.closed {
		t.Fatal("upstream was not closed after query audit failure")
	}
}

func TestSessionHandlerClosesUpstreamWhenPolicyRejectionAuditFails(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{result: &mysql.Result{}}
	logger := &recordingAuditLogger{err: errors.New("audit sink unavailable")}
	handler := newSessionHandlerWithAudit(
		testPolicyConfig(),
		nil,
		resourceLimits{},
		upstream,
		logger,
		auditIdentity{userID: "alice", sourceAddr: "10.0.0.1"},
	)

	_, err := handler.HandleQuery("drop table employees")
	assertUnsupported(t, err)
	if !upstream.closed {
		t.Fatal("upstream was not closed after policy rejection audit failure")
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

func TestSessionHandlerRejectsResultsetsOverMaxRows(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{
		result: resultWithTextRows(
			[]*mysql.Field{{Name: []byte("id"), Type: mysql.MYSQL_TYPE_LONG}},
			[][]*string{{stringPtr("1")}, {stringPtr("2")}},
		),
	}
	handler := newSessionHandlerWithLimits(
		testPolicyConfig(),
		nil,
		resourceLimits{maxResultRows: 1},
		upstream,
	)

	result, err := handler.HandleQuery("select id from employees")
	if result != nil {
		t.Fatalf("HandleQuery() result = %#v, want nil", result)
	}
	assertUnsupported(t, err)
	if !upstream.closed {
		t.Fatal("upstream was not closed after result row limit breach")
	}
}

func TestSessionHandlerAllowsResultsetsAtMaxRowsBoundary(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{
		result: resultWithTextRows(
			[]*mysql.Field{{Name: []byte("id"), Type: mysql.MYSQL_TYPE_LONG}},
			[][]*string{{stringPtr("1")}},
		),
	}
	handler := newSessionHandlerWithLimits(
		testPolicyConfig(),
		nil,
		resourceLimits{maxResultRows: 1},
		upstream,
	)

	result, err := handler.HandleQuery("select id from employees")
	if err != nil {
		t.Fatalf("HandleQuery() error = %v, want nil", err)
	}
	if result != upstream.result {
		t.Fatal("HandleQuery() did not return upstream result")
	}
	if upstream.closed {
		t.Fatal("upstream was closed at result row limit boundary")
	}
}

func TestSessionHandlerAllowsZeroRowBufferedResultsetWithStaleStreamingState(t *testing.T) {
	t.Parallel()

	resultset := mysql.NewResultset(1)
	resultset.Fields[0] = &mysql.Field{Name: []byte("id"), Type: mysql.MYSQL_TYPE_LONG}
	resultset.Streaming = mysql.StreamingSelect
	resultset.StreamingDone = true
	upstream := &recordingUpstream{result: mysql.NewResult(resultset)}
	handler := newSessionHandlerWithLimits(
		testPolicyConfig(),
		nil,
		resourceLimits{maxResultRows: 1},
		upstream,
	)

	result, err := handler.HandleQuery("select id from employees where 1 = 0")
	if err != nil {
		t.Fatalf("HandleQuery() error = %v, want nil", err)
	}
	if result.Streaming != mysql.StreamingNone || result.StreamingDone {
		t.Fatalf("result streaming state = (%v, %v), want normalized buffered result", result.Streaming, result.StreamingDone)
	}
	if upstream.closed {
		t.Fatal("upstream was closed for zero-row buffered resultset")
	}
}

func TestSessionHandlerRejectsStreamingResultsetsWhenRowLimitIsEnabled(t *testing.T) {
	t.Parallel()

	stream := mysql.NewStreamResult(
		[]*mysql.Field{{Name: []byte("id"), Type: mysql.MYSQL_TYPE_LONG}},
		1,
		false,
	)
	upstream := &recordingUpstream{result: stream.AsResult()}
	handler := newSessionHandlerWithLimits(
		testPolicyConfig(),
		nil,
		resourceLimits{maxResultRows: 1},
		upstream,
	)

	result, err := handler.HandleQuery("select id from employees")
	if result != nil {
		t.Fatalf("HandleQuery() result = %#v, want nil", result)
	}
	assertUnsupported(t, err)
	if !upstream.closed {
		t.Fatal("upstream was not closed after streaming result with row limit")
	}
	if !stream.IsClosed() {
		t.Fatal("stream result was not closed after row limit rejection")
	}
}

func TestSessionHandlerUsesBoundedStreamingReadForResultRowLimit(t *testing.T) {
	t.Parallel()

	upstream := &streamingRecordingUpstream{
		fields: []*mysql.Field{{Name: []byte("id"), Type: mysql.MYSQL_TYPE_LONG}},
		rows:   [][]*string{{stringPtr("1")}, {stringPtr("2")}, {stringPtr("3")}},
	}
	handler := newSessionHandlerWithLimits(
		testPolicyConfig(),
		nil,
		resourceLimits{maxResultRows: 1},
		upstream,
	)

	result, err := handler.HandleQuery("select id from employees")
	if result != nil {
		t.Fatalf("HandleQuery() result = %#v, want nil", result)
	}
	assertUnsupported(t, err)
	if upstream.executeCalls != 0 {
		t.Fatalf("buffered Execute calls = %d, want 0", upstream.executeCalls)
	}
	if upstream.streamingCalls != 1 {
		t.Fatalf("ExecuteSelectStreaming calls = %d, want 1", upstream.streamingCalls)
	}
	if upstream.callbackRows != 2 {
		t.Fatalf("streamed callback rows = %d, want limit plus one", upstream.callbackRows)
	}
	if !upstream.closed {
		t.Fatal("upstream was not closed after bounded streaming row limit breach")
	}
}

func TestSessionHandlerMasksBoundedStreamingResultAtRowLimitBoundary(t *testing.T) {
	t.Parallel()

	upstream := &streamingRecordingUpstream{
		fields: []*mysql.Field{{
			Schema:   []byte("app"),
			Name:     []byte("email"),
			OrgTable: []byte("employees"),
			OrgName:  []byte("email"),
			Type:     mysql.MYSQL_TYPE_VAR_STRING,
		}},
		rows: [][]*string{{stringPtr("alice@example.test")}},
	}
	handler := newSessionHandlerWithLimits(
		testPolicyConfig(),
		masking.NewPolicy(masking.Config{}),
		resourceLimits{maxResultRows: 1},
		upstream,
	)

	result, err := handler.HandleQuery("select email from employees")
	if err != nil {
		t.Fatalf("HandleQuery() error = %v, want nil", err)
	}
	if upstream.executeCalls != 0 {
		t.Fatalf("buffered Execute calls = %d, want 0", upstream.executeCalls)
	}
	if upstream.streamingCalls != 1 {
		t.Fatalf("ExecuteSelectStreaming calls = %d, want 1", upstream.streamingCalls)
	}
	if result.Streaming != mysql.StreamingNone || result.StreamingDone {
		t.Fatalf("result streaming state = (%v, %v), want buffered result", result.Streaming, result.StreamingDone)
	}
	values, err := result.RowDatas[0].Parse(result.Fields, false, nil)
	if err != nil {
		t.Fatalf("parse masked row data: %v", err)
	}
	if got := fieldValueText(t, values[0]); got != "***MASKED***" {
		t.Fatalf("RowDatas masked value = %q, want mask placeholder", got)
	}
	if got := fieldValueText(t, result.Values[0][0]); got != "***MASKED***" {
		t.Fatalf("Values masked value = %q, want mask placeholder", got)
	}
}

func TestSessionHandlerRejectsResultsetsOverMaxBytes(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{
		result: resultWithTextRows(
			[]*mysql.Field{{Name: []byte("email"), Type: mysql.MYSQL_TYPE_VAR_STRING}},
			[][]*string{{stringPtr("alice@example.test")}},
		),
	}
	handler := newSessionHandlerWithLimits(
		testPolicyConfig(),
		nil,
		resourceLimits{maxResultBytes: int64(len(upstream.result.RowDatas[0]) - 1)},
		upstream,
	)

	result, err := handler.HandleQuery("select email from employees")
	if result != nil {
		t.Fatalf("HandleQuery() result = %#v, want nil", result)
	}
	assertUnsupported(t, err)
	if !upstream.closed {
		t.Fatal("upstream was not closed after result byte limit breach")
	}
}

func TestSessionHandlerAllowsResultsetsAtMaxBytesBoundary(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{
		result: resultWithTextRows(
			[]*mysql.Field{{Name: []byte("email"), Type: mysql.MYSQL_TYPE_VAR_STRING}},
			[][]*string{{stringPtr("alice@example.test")}},
		),
	}
	handler := newSessionHandlerWithLimits(
		testPolicyConfig(),
		nil,
		resourceLimits{maxResultBytes: int64(len(upstream.result.RowDatas[0]))},
		upstream,
	)

	result, err := handler.HandleQuery("select email from employees")
	if err != nil {
		t.Fatalf("HandleQuery() error = %v, want nil", err)
	}
	if result != upstream.result {
		t.Fatal("HandleQuery() did not return upstream result")
	}
	if upstream.closed {
		t.Fatal("upstream was closed at result byte limit boundary")
	}
}

func TestSessionHandlerRejectsValuesOnlyResultsetsOverMaxBytes(t *testing.T) {
	t.Parallel()

	result := resultWithTextRows(
		[]*mysql.Field{{Name: []byte("email"), Type: mysql.MYSQL_TYPE_VAR_STRING}},
		[][]*string{{stringPtr("alice@example.test")}},
	)
	result.RowDatas = nil
	upstream := &recordingUpstream{result: result}
	handler := newSessionHandlerWithLimits(
		testPolicyConfig(),
		nil,
		resourceLimits{maxResultBytes: 1},
		upstream,
	)

	_, err := handler.HandleQuery("select email from employees")
	assertUnsupported(t, err)
	if len(result.RowDatas) == 0 {
		t.Fatal("Values-only result was not normalized to encoded RowDatas before byte limit")
	}
	if !upstream.closed {
		t.Fatal("upstream was not closed after values-only result byte limit breach")
	}
}

func TestSessionHandlerUsesBoundedStreamingReadForResultByteLimit(t *testing.T) {
	t.Parallel()

	upstream := &streamingRecordingUpstream{
		fields: []*mysql.Field{{Name: []byte("email"), Type: mysql.MYSQL_TYPE_VAR_STRING}},
		rows: [][]*string{
			{stringPtr("a@example.test")},
			{stringPtr("b@example.test")},
			{stringPtr("c@example.test")},
		},
	}
	firstRowSize := len(resultWithTextRows(upstream.fields, upstream.rows[:1]).RowDatas[0])
	handler := newSessionHandlerWithLimits(
		testPolicyConfig(),
		nil,
		resourceLimits{maxResultBytes: int64(firstRowSize)},
		upstream,
	)

	result, err := handler.HandleQuery("select email from employees")
	if result != nil {
		t.Fatalf("HandleQuery() result = %#v, want nil", result)
	}
	assertUnsupported(t, err)
	if upstream.executeCalls != 0 {
		t.Fatalf("buffered Execute calls = %d, want 0", upstream.executeCalls)
	}
	if upstream.streamingCalls != 1 {
		t.Fatalf("ExecuteSelectStreaming calls = %d, want 1", upstream.streamingCalls)
	}
	if upstream.callbackRows != 2 {
		t.Fatalf("streamed callback rows = %d, want first row plus overflow row", upstream.callbackRows)
	}
	if !upstream.closed {
		t.Fatal("upstream was not closed after bounded streaming byte limit breach")
	}
}

func TestSessionHandlerRejectsMaskedResultsetsOverMaxBytes(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{
		result: resultWithTextRows(
			[]*mysql.Field{{
				Schema:   []byte("app"),
				Name:     []byte("email"),
				OrgTable: []byte("employees"),
				OrgName:  []byte("email"),
				Type:     mysql.MYSQL_TYPE_VAR_STRING,
			}},
			[][]*string{{stringPtr("x")}},
		),
	}
	handler := newSessionHandlerWithLimits(
		testPolicyConfig(),
		masking.NewPolicy(masking.Config{}),
		resourceLimits{maxResultBytes: int64(len(upstream.result.RowDatas[0]))},
		upstream,
	)

	result, err := handler.HandleQuery("select email from employees")
	if result != nil {
		t.Fatalf("HandleQuery() result = %#v, want nil", result)
	}
	assertUnsupported(t, err)
	if !upstream.closed {
		t.Fatal("upstream was not closed after masked result byte limit breach")
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

type streamingRecordingUpstream struct {
	recordingUpstream

	fields         []*mysql.Field
	rows           [][]*string
	streamingCalls int
	callbackRows   int
}

func (upstream *streamingRecordingUpstream) ExecuteSelectStreaming(
	command string,
	result *mysql.Result,
	perRowCallback client.SelectPerRowCallback,
	perResultCallback client.SelectPerResultCallback,
) error {
	upstream.streamingCalls++
	upstream.query = command

	buffered := resultWithTextRows(upstream.fields, upstream.rows)
	result.Resultset = buffered.Resultset
	result.Streaming = mysql.StreamingSelect
	if perResultCallback != nil {
		if err := perResultCallback(result); err != nil {
			return err
		}
	}
	for _, row := range buffered.Values {
		upstream.callbackRows++
		if err := perRowCallback(row); err != nil {
			return err
		}
	}
	result.StreamingDone = true

	return nil
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

type recordingAuditLogger struct {
	events    []audit.Event
	err       error
	errOnCall int
}

func (logger *recordingAuditLogger) Log(_ context.Context, event audit.Event) error {
	logger.events = append(logger.events, event)
	if logger.errOnCall > 0 && len(logger.events) != logger.errOnCall {
		return nil
	}

	return logger.err
}

func (logger *recordingAuditLogger) singleEvent(t *testing.T) audit.Event {
	t.Helper()

	if len(logger.events) != 1 {
		t.Fatalf("audit event count = %d, want 1: %#v", len(logger.events), logger.events)
	}

	return logger.events[0]
}
