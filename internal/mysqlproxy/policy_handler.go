package mysqlproxy

import (
	"strconv"

	"github.com/dakatsuka/masqman/internal/sqlpolicy"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
)

const queryPolicyPrivilege = "Masqman query policy"

type policyHandler struct {
	classifier     sqlpolicy.Classifier
	allowedSchemas map[string]struct{}
	limits         resourceLimits
	next           server.Handler
}

type resourceLimits struct {
	maxQueryBytes int
}

type queryDecisionHandler interface {
	setQueryDecision(sqlpolicy.Decision)
}

func newPolicyHandler(config sqlpolicy.Config, next server.Handler) *policyHandler {
	return newPolicyHandlerWithLimits(config, resourceLimits{}, next)
}

func newPolicyHandlerWithLimits(
	config sqlpolicy.Config,
	limits resourceLimits,
	next server.Handler,
) *policyHandler {
	if next == nil {
		next = &unsupportedHandler{}
	}

	return &policyHandler{
		classifier:     sqlpolicy.NewClassifier(config),
		allowedSchemas: allowedSchemaSet(config.AllowedSchemas),
		limits:         limits,
		next:           next,
	}
}

func (handler *policyHandler) UseDB(database string) error {
	if !handler.isAllowedSchema(database) {
		return policyError()
	}

	return handler.next.UseDB(database)
}

func (handler *policyHandler) HandleQuery(query string) (*mysql.Result, error) {
	if handler.limits.maxQueryBytes > 0 && len(query) > handler.limits.maxQueryBytes {
		return nil, queryTooLargeError()
	}

	decision := handler.classifier.Classify(query)
	if !isAllowedDecision(decision) {
		return nil, policyError()
	}
	if handler.shouldSynthesizeMaxAllowedPacket(decision) {
		return maxAllowedPacketResult(handler.limits.maxQueryBytes), nil
	}
	if next, ok := handler.next.(queryDecisionHandler); ok {
		next.setQueryDecision(decision)
	}

	return handler.next.HandleQuery(query)
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
