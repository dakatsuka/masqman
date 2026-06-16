// Package mysqlproxy adapts Masqman policy and masking modules to the MySQL wire protocol.
package mysqlproxy

import (
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
)

const unsupportedProtocolSurface = "Masqman M1 protocol surface"

type unsupportedHandler struct{}

func (handler *unsupportedHandler) UseDB(_ string) error {
	return unsupportedError()
}

func (handler *unsupportedHandler) HandleQuery(_ string) (*mysql.Result, error) {
	return nil, unsupportedError()
}

func (handler *unsupportedHandler) HandleFieldList(_, _ string) ([]*mysql.Field, error) {
	return nil, unsupportedError()
}

func (handler *unsupportedHandler) HandleStmtPrepare(_ string) (int, int, any, error) {
	return 0, 0, nil, unsupportedError()
}

func (handler *unsupportedHandler) HandleStmtExecute(_ any, _ string, _ []any) (*mysql.Result, error) {
	return nil, unsupportedError()
}

func (handler *unsupportedHandler) HandleStmtClose(_ any) error {
	return unsupportedError()
}

func (handler *unsupportedHandler) HandleOtherCommand(_ byte, _ []byte) error {
	return unsupportedError()
}

func newAuthenticationHandler() *server.InMemoryAuthenticationHandler {
	return server.NewInMemoryAuthenticationHandler(mysql.AUTH_CACHING_SHA2_PASSWORD)
}

func unsupportedError() *mysql.MyError {
	return mysql.NewDefaultError(mysql.ER_NOT_SUPPORTED_YET, unsupportedProtocolSurface)
}
