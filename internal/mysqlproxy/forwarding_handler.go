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

type forwardingHandler struct {
	unsupportedHandler

	upstream upstreamSession
	masker   masking.Policy
	decision sqlpolicy.Decision
	closed   bool
	terminal error
}

func newForwardingHandler(upstream upstreamSession) *forwardingHandler {
	return newForwardingHandlerWithMasking(upstream, nil)
}

func newForwardingHandlerWithMasking(upstream upstreamSession, masker masking.Policy) *forwardingHandler {
	return &forwardingHandler{
		upstream: upstream,
		masker:   masker,
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
	return newPolicyHandler(config, newForwardingHandlerWithMasking(upstream, masker))
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

	result, err := handler.upstream.Execute(query)
	if err != nil {
		if isTerminalUpstreamError(err) {
			_ = handler.closeTerminal(err)
		}

		return nil, err
	}
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
	if err := handler.maskResult(result); err != nil {
		_ = handler.closeTerminal(err)

		return nil, unsupportedError()
	}

	return result, nil
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
	if result.IsStreaming() {
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
	return result != nil && (result.IsStreaming() || result.HasResultset())
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
		rowData := make(mysql.RowData, 0)
		for _, value := range row {
			raw, err := fieldValueBytes(value)
			if err != nil {
				return nil, err
			}
			rowData = appendMaskingValue(rowData, raw)
		}
		rowDatas = append(rowDatas, rowData)
	}

	return rowDatas, nil
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
