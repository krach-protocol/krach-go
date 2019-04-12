package krach

import (
	"net"

	"github.com/pkg/errors"
	"github.com/xtaci/smux"
	"gopkg.in/noisesocket.v0"
)

type Listener struct {
	nsListener net.Listener
	config     *Config
}

func (l *Listener) Accept() (*Session, error) {
	conn, err := l.nsListener.Accept()
	if err != nil {
		return nil, errors.Wrap(err, errPrefix+"Failed to accept noisesocket connection")
	}
	sess, err := smux.Server(conn, l.config.Config)
	if err != nil {
		return nil, errors.Wrap(err, errPrefix+"Failed to open multiplexing session")
	}

	return newSession(conn, sess), nil
}

func (l *Listener) Close() error {
	return l.nsListener.Close()
}

func (l *Listener) Addr() net.Addr {
	return l.nsListener.Addr()
}

func Listen(addr string, config *Config) (*Listener, error) {
	nsListener, err := noisesocket.Listen(addr, config.ConnectionConfig)
	if err != nil {
		return nil, errors.Wrapf(err, errPrefix+"Failed to open noisesocket connection to %s", addr)
	}
	return &Listener{
		nsListener: nsListener,
		config:     config,
	}, nil
}
