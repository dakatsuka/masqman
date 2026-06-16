package mysqlproxy

import (
	"github.com/dakatsuka/masqman/internal/sqlpolicy"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
)

const queryPolicyPrivilege = "Masqman query policy"

type policyHandler struct {
	classifier     sqlpolicy.Classifier
	allowedSchemas map[string]struct{}
	next           server.Handler
}

func newPolicyHandler(config sqlpolicy.Config, next server.Handler) *policyHandler {
	if next == nil {
		next = &unsupportedHandler{}
	}

	return &policyHandler{
		classifier:     sqlpolicy.NewClassifier(config),
		allowedSchemas: allowedSchemaSet(config.AllowedSchemas),
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
	if !handler.isAllowed(query) {
		return nil, policyError()
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

func (handler *policyHandler) isAllowed(statement string) bool {
	decision := handler.classifier.Classify(statement)

	return decision.Kind == sqlpolicy.AllowRead ||
		decision.Kind == sqlpolicy.AllowOperationalRead ||
		decision.Kind == sqlpolicy.AllowSetup
}

func policyError() *mysql.MyError {
	return mysql.NewDefaultError(mysql.ER_SPECIFIC_ACCESS_DENIED_ERROR, queryPolicyPrivilege)
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
