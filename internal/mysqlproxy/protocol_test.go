package mysqlproxy

import (
	"errors"
	"testing"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
)

func TestUnsupportedHandlerImplementsServerProtocol(t *testing.T) {
	t.Parallel()

	handler := &unsupportedHandler{}

	assertUnsupported(t, handler.UseDB("app"))

	_, err := handler.HandleQuery("select 1")
	assertUnsupported(t, err)

	_, err = handler.HandleFieldList("employees", "%")
	assertUnsupported(t, err)

	_, _, _, err = handler.HandleStmtPrepare("select ?")
	assertUnsupported(t, err)

	_, err = handler.HandleStmtExecute(nil, "select ?", []any{1})
	assertUnsupported(t, err)

	assertUnsupported(t, handler.HandleStmtClose(nil))
	assertUnsupported(t, handler.HandleOtherCommand(mysql.COM_PROCESS_KILL, nil))
}

func TestAuthenticationHandlerUsesCachingSHA2(t *testing.T) {
	t.Parallel()

	handler := newAuthenticationHandler()

	if err := handler.AddUser("alice", "secret"); err != nil {
		t.Fatalf("AddUser() error = %v, want nil", err)
	}

	credential, found, err := handler.GetCredential("alice")
	if err != nil {
		t.Fatalf("GetCredential() error = %v, want nil", err)
	}
	if !found {
		t.Fatal("GetCredential() found = false, want true")
	}
	if credential.AuthPluginName != mysql.AUTH_CACHING_SHA2_PASSWORD {
		t.Fatalf("AuthPluginName = %q, want %q", credential.AuthPluginName, mysql.AUTH_CACHING_SHA2_PASSWORD)
	}
}

func assertUnsupported(t *testing.T, err error) {
	t.Helper()

	assertMySQLErrorCode(t, err, mysql.ER_NOT_SUPPORTED_YET)
}

func assertMySQLErrorCode(t *testing.T, err error, code uint16) {
	t.Helper()

	var mysqlErr *mysql.MyError
	if !errors.As(err, &mysqlErr) {
		t.Fatalf("error = %v, want *mysql.MyError", err)
	}
	if mysqlErr.Code != code {
		t.Fatalf("error code = %d, want %d", mysqlErr.Code, code)
	}
}

var (
	_ server.Handler               = (*unsupportedHandler)(nil)
	_ server.AuthenticationHandler = newAuthenticationHandler()
)
