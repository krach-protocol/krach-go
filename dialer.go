package krach

import (
	"github.com/pkg/errors"
	"github.com/xtaci/smux"
	"gopkg.in/noisesocket.v0"
)

func Dial(addr string, config *Config) (*Session, error) {
	nsConn, err := noisesocket.Dial(addr, config.ConnectionConfig)
	if err != nil {
		return nil, errors.Wrapf(err, errPrefix+"Failed to dial %s", addr)
	}

	sess, err := smux.Client(nsConn, config.Config)
	if err != nil {
		return nil, errors.Wrapf(err, errPrefix+"Failed to create session with %s", addr)
	}
	return newSession(nsConn, sess), nil
}
