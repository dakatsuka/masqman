package mysqlproxy

import (
	"errors"
	"fmt"

	"github.com/dakatsuka/masqman/internal/masking"
	"github.com/dakatsuka/masqman/internal/sqlpolicy"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
)

type upstreamSession interface {
	UseDB(database string) error
	Execute(query string, args ...any) (*mysql.Result, error)
	Close() error
}

type streamingUpstreamSession interface {
	ExecuteSelectStreaming(
		command string,
		result *mysql.Result,
		perRowCallback client.SelectPerRowCallback,
		perResultCallback client.SelectPerResultCallback,
	) error
}

type forwardingHandler struct {
	unsupportedHandler

	upstream upstreamSession
	masker   masking.Policy
	limits   resourceLimits
	decision sqlpolicy.Decision
	closed   bool
	terminal error
}

func newForwardingHandler(upstream upstreamSession) *forwardingHandler {
	return newForwardingHandlerWithMasking(upstream, nil)
}

func newForwardingHandlerWithMasking(upstream upstreamSession, masker masking.Policy) *forwardingHandler {
	return newForwardingHandlerWithLimits(upstream, masker, resourceLimits{})
}

func newForwardingHandlerWithLimits(
	upstream upstreamSession,
	masker masking.Policy,
	limits resourceLimits,
) *forwardingHandler {
	return &forwardingHandler{
		upstream: upstream,
		masker:   masker,
		limits:   limits,
	}
}

func newSessionHandler(config sqlpolicy.Config, upstream upstreamSession) server.Handler {
	return newSessionHandlerWithMasking(config, nil, upstream)
}

func newSessionHandlerWithMasking(
	config sqlpolicy.Config,
	masker masking.Policy,
	upstream upstreamSession,
) server.Handler {
	return newSessionHandlerWithLimits(config, masker, resourceLimits{}, upstream)
}

func newSessionHandlerWithLimits(
	config sqlpolicy.Config,
	masker masking.Policy,
	limits resourceLimits,
	upstream upstreamSession,
) server.Handler {
	return newPolicyHandlerWithLimits(config, limits, newForwardingHandlerWithLimits(upstream, masker, limits))
}

func (handler *forwardingHandler) UseDB(database string) error {
	if handler.closed {
		return unsupportedError()
	}

	err := handler.upstream.UseDB(database)
	if isTerminalUpstreamError(err) {
		_ = handler.closeTerminal(err)
	}

	return err
}

func (handler *forwardingHandler) HandleQuery(query string) (*mysql.Result, error) {
	if handler.closed {
		return nil, unsupportedError()
	}

	result, err := handler.execute(query)
	if err != nil {
		if errors.Is(err, errResultRowLimitExceeded) || errors.Is(err, errResultByteLimitExceeded) {
			_ = handler.closeTerminal(err)

			return nil, unsupportedError()
		}
		if isTerminalUpstreamError(err) {
			_ = handler.closeTerminal(err)
		}

		return nil, err
	}
	normalizeBufferedResultset(result)
	if result != nil && result.Status&mysql.SERVER_MORE_RESULTS_EXISTS != 0 {
		err := unsupportedError()
		_ = handler.closeTerminal(err)

		return nil, err
	}
	if handler.decision.Kind == sqlpolicy.AllowSetup && resultHasResultset(result) {
		err := unsupportedError()
		_ = handler.closeTerminal(err)

		return nil, err
	}
	if handler.limits.maxResultRows > 0 && resultIsStreaming(result) {
		err := unsupportedError()
		result.Close()
		_ = handler.closeTerminal(err)

		return nil, err
	}
	if handler.limits.maxResultBytes > 0 && resultIsStreaming(result) {
		err := unsupportedError()
		result.Close()
		_ = handler.closeTerminal(err)

		return nil, err
	}
	if err := ensureBufferedRowDatas(result); err != nil {
		_ = handler.closeTerminal(err)

		return nil, unsupportedError()
	}
	if handler.resultRowsOverLimit(result) {
		err := unsupportedError()
		_ = handler.closeTerminal(err)

		return nil, err
	}
	if handler.resultBytesOverLimit(result) {
		err := unsupportedError()
		_ = handler.closeTerminal(err)

		return nil, err
	}
	if err := handler.maskResult(result); err != nil {
		_ = handler.closeTerminal(err)

		return nil, unsupportedError()
	}
	if handler.resultBytesOverLimit(result) {
		err := unsupportedError()
		_ = handler.closeTerminal(err)

		return nil, err
	}

	return result, nil
}

func (handler *forwardingHandler) execute(query string) (*mysql.Result, error) {
	if handler.limits.maxResultRows > 0 || handler.limits.maxResultBytes > 0 {
		if upstream, ok := handler.upstream.(streamingUpstreamSession); ok {
			return handler.executeBoundedSelect(query, upstream)
		}
	}

	return handler.upstream.Execute(query)
}

func (handler *forwardingHandler) executeBoundedSelect(
	query string,
	upstream streamingUpstreamSession,
) (*mysql.Result, error) {
	result := &mysql.Result{}
	var rows [][]mysql.FieldValue
	var rowDatas []mysql.RowData
	var resultBytes int64
	err := upstream.ExecuteSelectStreaming(
		query,
		result,
		func(row []mysql.FieldValue) error {
			if handler.limits.maxResultRows > 0 && len(rows) >= handler.limits.maxResultRows {
				return errResultRowLimitExceeded
			}
			cloned := cloneFieldValues(row)
			rowData, err := rowDataFromValues(cloned)
			if err != nil {
				return err
			}
			if handler.limits.maxResultBytes > 0 &&
				resultBytes+int64(len(rowData)) > handler.limits.maxResultBytes {
				return errResultByteLimitExceeded
			}
			rows = append(rows, cloned)
			rowDatas = append(rowDatas, rowData)
			resultBytes += int64(len(rowData))

			return nil
		},
		nil,
	)
	if err != nil {
		return nil, err
	}
	if result.Resultset != nil && len(result.Fields) > 0 {
		result.RowDatas = rowDatas
		result.Values = rows
		result.Streaming = mysql.StreamingNone
		result.StreamingDone = false
	}

	return result, nil
}

func (handler *forwardingHandler) resultRowsOverLimit(result *mysql.Result) bool {
	return handler.limits.maxResultRows > 0 && resultRowCount(result) > handler.limits.maxResultRows
}

func (handler *forwardingHandler) resultBytesOverLimit(result *mysql.Result) bool {
	return handler.limits.maxResultBytes > 0 && resultEncodedBytes(result) > handler.limits.maxResultBytes
}

func (handler *forwardingHandler) Close() error {
	if handler.closed {
		return nil
	}
	handler.closed = true

	return handler.upstream.Close()
}

func (handler *forwardingHandler) isClosed() bool {
	return handler.closed
}

func (handler *forwardingHandler) terminalError() error {
	return handler.terminal
}

func (handler *forwardingHandler) closeTerminal(err error) error {
	if handler.terminal == nil {
		handler.terminal = err
	}

	return handler.Close()
}

func (handler *forwardingHandler) setQueryDecision(decision sqlpolicy.Decision) {
	handler.decision = decision
}

func (handler *forwardingHandler) maskResult(result *mysql.Result) error {
	if handler.masker == nil || result == nil {
		return nil
	}
	if resultIsStreaming(result) {
		return errors.New("streaming resultsets cannot be masked")
	}
	if result.Resultset == nil || len(result.Fields) == 0 {
		return nil
	}

	rowDatas := result.RowDatas
	if len(rowDatas) == 0 && len(result.Values) > 0 {
		var err error
		rowDatas, err = rowDatasFromValues(result.Values)
		if err != nil {
			return err
		}
	}

	values := make([][]mysql.FieldValue, 0, len(rowDatas))
	maskedRows := make([]mysql.RowData, 0, len(rowDatas))
	for _, rowData := range rowDatas {
		rowValues, err := rowData.Parse(result.Fields, false, nil)
		if err != nil {
			return fmt.Errorf("parse upstream text row: %w", err)
		}

		maskedRow, maskedValues, err := handler.maskRow(result.Fields, rowValues)
		if err != nil {
			return err
		}
		maskedRows = append(maskedRows, maskedRow)
		values = append(values, maskedValues)
	}

	result.RowDatas = maskedRows
	result.Values = values

	return nil
}

func (handler *forwardingHandler) maskRow(
	fields []*mysql.Field,
	values []mysql.FieldValue,
) (mysql.RowData, []mysql.FieldValue, error) {
	if len(values) != len(fields) {
		return nil, nil, fmt.Errorf("row has %d values for %d fields", len(values), len(fields))
	}

	rowData := make(mysql.RowData, 0)
	for i, value := range values {
		raw, err := fieldValueBytes(value)
		if err != nil {
			return nil, nil, err
		}

		masked := raw
		if !handler.expressionAllowsPassthrough(i, fields[i], len(fields)) {
			masked = handler.masker.Mask(maskingField(fields[i]), raw)
		}
		rowData = appendMaskingValue(rowData, masked)
	}

	maskedValues, err := rowData.Parse(fields, false, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("parse masked text row: %w", err)
	}

	return rowData, maskedValues, nil
}

func (handler *forwardingHandler) expressionAllowsPassthrough(index int, field *mysql.Field, fieldCount int) bool {
	contexts := handler.decision.ExpressionContext
	if len(contexts) != fieldCount {
		return false
	}
	if !originFreeField(field) {
		return false
	}

	context := contexts[index]
	if context.SafeBuiltin || context.Kind == sqlpolicy.ExpressionCountStar {
		return true
	}

	return handler.decision.Kind == sqlpolicy.AllowOperationalRead &&
		context.Kind == sqlpolicy.ExpressionLiteral
}

func resultHasResultset(result *mysql.Result) bool {
	return result != nil && (resultIsStreaming(result) || result.HasResultset())
}

func resultIsStreaming(result *mysql.Result) bool {
	return result != nil &&
		(result.IsStreaming() ||
			(result.Resultset != nil && result.Streaming != mysql.StreamingNone))
}

func normalizeBufferedResultset(result *mysql.Result) {
	if result == nil || result.Resultset == nil {
		return
	}
	if len(result.Fields) == 0 && len(result.RowDatas) == 0 && len(result.Values) == 0 {
		return
	}

	result.Streaming = mysql.StreamingNone
	result.StreamingDone = false
}

func resultRowCount(result *mysql.Result) int {
	if result == nil || result.Resultset == nil {
		return 0
	}
	if len(result.RowDatas) > 0 {
		return len(result.RowDatas)
	}

	return len(result.Values)
}

func resultEncodedBytes(result *mysql.Result) int64 {
	if result == nil || result.Resultset == nil {
		return 0
	}

	var size int64
	for _, rowData := range result.RowDatas {
		size += int64(len(rowData))
	}

	return size
}

func ensureBufferedRowDatas(result *mysql.Result) error {
	if result == nil || result.Resultset == nil || len(result.RowDatas) > 0 || len(result.Values) == 0 {
		return nil
	}

	rowDatas, err := rowDatasFromValues(result.Values)
	if err != nil {
		return err
	}
	result.RowDatas = rowDatas

	return nil
}

func originFreeField(field *mysql.Field) bool {
	return field == nil ||
		(len(field.Schema) == 0 && len(field.OrgTable) == 0 && len(field.OrgName) == 0)
}

func fieldValueBytes(value mysql.FieldValue) (masking.Value, error) {
	if value.Value() == nil {
		return masking.Value{Null: true}, nil
	}

	raw, err := mysql.FormatTextValue(value.Value())
	if err != nil {
		return masking.Value{}, fmt.Errorf("format text value: %w", err)
	}

	return masking.Value{Raw: raw}, nil
}

func appendMaskingValue(rowData mysql.RowData, value masking.Value) mysql.RowData {
	if value.Null {
		return append(rowData, 0xfb)
	}

	return append(rowData, mysql.PutLengthEncodedString(value.Raw)...)
}

func rowDatasFromValues(values [][]mysql.FieldValue) ([]mysql.RowData, error) {
	rowDatas := make([]mysql.RowData, 0, len(values))
	for _, row := range values {
		rowData, err := rowDataFromValues(row)
		if err != nil {
			return nil, err
		}
		rowDatas = append(rowDatas, rowData)
	}

	return rowDatas, nil
}

func rowDataFromValues(values []mysql.FieldValue) (mysql.RowData, error) {
	rowData := make(mysql.RowData, 0)
	for _, value := range values {
		raw, err := fieldValueBytes(value)
		if err != nil {
			return nil, err
		}
		rowData = appendMaskingValue(rowData, raw)
	}

	return rowData, nil
}

func cloneFieldValues(values []mysql.FieldValue) []mysql.FieldValue {
	cloned := make([]mysql.FieldValue, len(values))
	for i, value := range values {
		var raw []byte
		if value.Type == mysql.FieldValueTypeString {
			raw = append([]byte(nil), value.AsString()...)
		}
		cloned[i] = mysql.NewFieldValue(value.Type, value.AsUint64(), raw)
	}

	return cloned
}

func maskingField(field *mysql.Field) masking.Field {
	if field == nil {
		return masking.Field{}
	}

	return masking.Field{
		Schema:         string(field.Schema),
		OriginalTable:  string(field.OrgTable),
		OriginalColumn: string(field.OrgName),
		TypeFamily:     maskingTypeFamily(field.Type, field.Flag),
	}
}

func maskingTypeFamily(mysqlType uint8, flag uint16) masking.TypeFamily {
	switch mysqlType {
	case mysql.MYSQL_TYPE_TINY,
		mysql.MYSQL_TYPE_SHORT,
		mysql.MYSQL_TYPE_LONG,
		mysql.MYSQL_TYPE_FLOAT,
		mysql.MYSQL_TYPE_DOUBLE,
		mysql.MYSQL_TYPE_LONGLONG,
		mysql.MYSQL_TYPE_INT24,
		mysql.MYSQL_TYPE_YEAR,
		mysql.MYSQL_TYPE_DECIMAL,
		mysql.MYSQL_TYPE_NEWDECIMAL:
		return masking.TypeNumeric
	case mysql.MYSQL_TYPE_DATE, mysql.MYSQL_TYPE_NEWDATE:
		return masking.TypeDate
	case mysql.MYSQL_TYPE_TIME, mysql.MYSQL_TYPE_TIME2:
		return masking.TypeTime
	case mysql.MYSQL_TYPE_TIMESTAMP,
		mysql.MYSQL_TYPE_TIMESTAMP2,
		mysql.MYSQL_TYPE_DATETIME,
		mysql.MYSQL_TYPE_DATETIME2:
		return masking.TypeTimestamp
	case mysql.MYSQL_TYPE_BIT,
		mysql.MYSQL_TYPE_VECTOR,
		mysql.MYSQL_TYPE_TINY_BLOB,
		mysql.MYSQL_TYPE_MEDIUM_BLOB,
		mysql.MYSQL_TYPE_LONG_BLOB,
		mysql.MYSQL_TYPE_BLOB,
		mysql.MYSQL_TYPE_VAR_STRING,
		mysql.MYSQL_TYPE_STRING:
		if flag&mysql.BINARY_FLAG != 0 {
			return masking.TypeBinary
		}
	}

	return masking.TypeText
}

func isTerminalUpstreamError(err error) bool {
	if err == nil {
		return false
	}
	var mysqlErr *mysql.MyError

	return !errors.As(err, &mysqlErr)
}

var (
	_ server.Handler  = (*forwardingHandler)(nil)
	_ upstreamSession = (*client.Conn)(nil)
)

var (
	errResultRowLimitExceeded  = errors.New("result row limit exceeded")
	errResultByteLimitExceeded = errors.New("result byte limit exceeded")
)
