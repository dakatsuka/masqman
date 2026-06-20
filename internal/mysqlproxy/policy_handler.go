package mysqlproxy

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/dakatsuka/masqman/internal/audit"
	"github.com/dakatsuka/masqman/internal/sqlpolicy"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
)

const queryPolicyPrivilege = "Masqman query policy"

type policyHandler struct {
	classifier     sqlpolicy.Classifier
	allowedSchemas map[string]struct{}
	limits         resourceLimits
	auditor        audit.Logger
	identity       auditIdentity
	next           server.Handler
}

type resourceLimits struct {
	maxQueryBytes  int
	maxResultRows  int
	maxResultBytes int64
}

type queryDecisionHandler interface {
	setQueryDecision(sqlpolicy.Decision)
}

type queryAuditStatsHandler interface {
	maskedFieldCount() int
}

type auditIdentity struct {
	userID     string
	sourceAddr string
}

func newPolicyHandler(config sqlpolicy.Config, next server.Handler) *policyHandler {
	return newPolicyHandlerWithLimits(config, resourceLimits{}, next)
}

func newPolicyHandlerWithLimits(
	config sqlpolicy.Config,
	limits resourceLimits,
	next server.Handler,
) *policyHandler {
	return newPolicyHandlerWithAudit(config, limits, next, nil, auditIdentity{})
}

func newPolicyHandlerWithAudit(
	config sqlpolicy.Config,
	limits resourceLimits,
	next server.Handler,
	auditor audit.Logger,
	identity auditIdentity,
) *policyHandler {
	if next == nil {
		next = &unsupportedHandler{}
	}

	return &policyHandler{
		classifier:     sqlpolicy.NewClassifier(config),
		allowedSchemas: allowedSchemaSet(config.AllowedSchemas),
		limits:         limits,
		auditor:        auditor,
		identity:       identity,
		next:           next,
	}
}

func (handler *policyHandler) UseDB(database string) error {
	if !handler.isAllowedSchema(database) {
		return policyError()
	}

	return handler.next.UseDB(database)
}

func (handler *policyHandler) setAuditIdentity(identity auditIdentity) {
	handler.identity = identity
}

func (handler *policyHandler) HandleQuery(query string) (*mysql.Result, error) {
	if handler.limits.maxQueryBytes > 0 && len(query) > handler.limits.maxQueryBytes {
		if err := handler.auditQuery(query, sqlpolicy.Decision{Kind: sqlpolicy.Reject}, "query_too_large"); err != nil {
			handler.closeAfterAuditFailure()

			return nil, unsupportedError()
		}

		return nil, queryTooLargeError()
	}

	decision := handler.classifier.Classify(query)
	if !isAllowedDecision(decision) {
		if err := handler.auditQuery(query, decision, "policy_reject"); err != nil {
			handler.closeAfterAuditFailure()

			return nil, unsupportedError()
		}

		return nil, policyError()
	}
	if handler.shouldSynthesizeMaxAllowedPacket(decision) {
		if err := handler.auditQuery(query, decision, ""); err != nil {
			handler.closeAfterAuditFailure()

			return nil, unsupportedError()
		}

		return maxAllowedPacketResult(handler.limits.maxQueryBytes), nil
	}
	if next, ok := handler.next.(queryDecisionHandler); ok {
		next.setQueryDecision(decision)
	}

	result, err := handler.next.HandleQuery(query)
	if auditErr := handler.auditQuery(query, decision, queryErrorClass(err)); auditErr != nil {
		handler.closeAfterAuditFailure()

		return nil, unsupportedError()
	}

	return result, err
}

func (handler *policyHandler) HandleFieldList(_, _ string) ([]*mysql.Field, error) {
	return nil, unsupportedError()
}

func (handler *policyHandler) HandleStmtPrepare(_ string) (int, int, any, error) {
	return 0, 0, nil, unsupportedError()
}

func (handler *policyHandler) HandleStmtExecute(_ any, _ string, _ []any) (*mysql.Result, error) {
	return nil, unsupportedError()
}

func (handler *policyHandler) HandleStmtClose(_ any) error {
	return unsupportedError()
}

func (handler *policyHandler) HandleOtherCommand(_ byte, _ []byte) error {
	return unsupportedError()
}

func isAllowedDecision(decision sqlpolicy.Decision) bool {
	return decision.Kind == sqlpolicy.AllowRead ||
		decision.Kind == sqlpolicy.AllowOperationalRead ||
		decision.Kind == sqlpolicy.AllowSetup
}

func policyError() *mysql.MyError {
	return mysql.NewDefaultError(mysql.ER_SPECIFIC_ACCESS_DENIED_ERROR, queryPolicyPrivilege)
}

func queryTooLargeError() *mysql.MyError {
	return mysql.NewDefaultError(mysql.ER_NET_PACKET_TOO_LARGE)
}

func (handler *policyHandler) auditQuery(
	query string,
	decision sqlpolicy.Decision,
	errorClass string,
) error {
	if handler.auditor == nil {
		return nil
	}

	maskedFields := 0
	if stats, ok := handler.next.(queryAuditStatsHandler); ok {
		maskedFields = stats.maskedFieldCount()
	}

	return handler.auditor.Log(context.Background(), audit.Event{
		Time:                time.Now(),
		Kind:                audit.EventQuery,
		UserID:              handler.identity.userID,
		SourceAddr:          handler.identity.sourceAddr,
		NormalizedStatement: audit.NormalizeStatement(query),
		Decision:            string(decision.Kind),
		MaskedFields:        maskedFields,
		ErrorClass:          errorClass,
	})
}

func (handler *policyHandler) closeAfterAuditFailure() {
	if closer, ok := handler.next.(interface{ closeTerminal(error) error }); ok {
		_ = closer.closeTerminal(errAuditFailure)

		return
	}
	if closer, ok := handler.next.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
}

func queryErrorClass(err error) string {
	if err == nil {
		return ""
	}
	var mysqlErr *mysql.MyError
	if errors.As(err, &mysqlErr) {
		return "mysql_error"
	}

	return "proxy_error"
}

func (handler *policyHandler) shouldSynthesizeMaxAllowedPacket(decision sqlpolicy.Decision) bool {
	return handler.limits.maxQueryBytes > 0 &&
		decision.Kind == sqlpolicy.AllowOperationalRead &&
		len(decision.ExpressionContext) == 1 &&
		decision.ExpressionContext[0].FunctionName == "@@max_allowed_packet"
}

func maxAllowedPacketResult(limit int) *mysql.Result {
	field := &mysql.Field{
		Name: []byte("@@max_allowed_packet"),
		Type: mysql.MYSQL_TYPE_LONGLONG,
	}
	resultset := mysql.NewResultset(1)
	resultset.Fields[0] = field
	rowData := mysql.RowData(mysql.PutLengthEncodedString([]byte(strconv.Itoa(limit))))
	resultset.RowDatas = append(resultset.RowDatas, rowData)
	values, err := rowData.Parse(resultset.Fields, false, nil)
	if err == nil {
		resultset.Values = append(resultset.Values, values)
	}

	return mysql.NewResult(resultset)
}

func allowedSchemaSet(schemas []string) map[string]struct{} {
	allowed := make(map[string]struct{}, len(schemas))
	for _, schema := range schemas {
		allowed[schema] = struct{}{}
	}

	return allowed
}

func (handler *policyHandler) isAllowedSchema(database string) bool {
	_, ok := handler.allowedSchemas[database]

	return ok
}

var _ server.Handler = (*policyHandler)(nil)

var errAuditFailure = errors.New("audit failure")
