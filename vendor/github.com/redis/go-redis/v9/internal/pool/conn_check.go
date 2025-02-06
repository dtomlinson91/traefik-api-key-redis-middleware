package pool

import (
	"errors"
	"io"
	"net"
	"time"
)

var errUnexpectedRead = errors.New("unexpected read from socket")

func connCheck(conn net.Conn) error {
	// Reset previous timeout
	_ = conn.SetDeadline(time.Time{})

	// Set a very short read deadline
	err := conn.SetReadDeadline(time.Now().Add(time.Millisecond))
	if err != nil {
		return err
	}
	defer conn.SetReadDeadline(time.Time{}) // Reset deadline

	// Try to read 1 byte
	buf := make([]byte, 1)
	n, err := conn.Read(buf)

	if err == io.EOF {
		return io.EOF
	}

	if err, ok := err.(net.Error); ok && err.Timeout() {
		// Timeout means the connection is still alive but has no data
		return nil
	}

	if n > 0 {
		return errUnexpectedRead
	}

	if err != nil {
		return err
	}

	return nil
}
