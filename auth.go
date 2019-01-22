package socks5

import (
	"context"
	"fmt"
	"io"
)

const (
	NoAuth          = uint8(0)
	noAcceptable    = uint8(255)
	UserPassAuth    = uint8(2)
	userAuthVersion = uint8(1)
	authSuccess     = uint8(0)
	authFailure     = uint8(1)
)

var (
	UserAuthFailed  = fmt.Errorf("user authentication failed")
	NoSupportedAuth = fmt.Errorf("no supported authentication mechanism")
)

type Authenticator interface {
	Authenticate(ctx context.Context, reader io.Reader, writer io.Writer) (context.Context, error)
	GetCode() uint8
}

// NoAuthAuthenticator is used to handle the "No Authentication" mode
type NoAuthAuthenticator struct{}

func (a NoAuthAuthenticator) GetCode() uint8 {
	return NoAuth
}

func (a NoAuthAuthenticator) Authenticate(ctx context.Context, reader io.Reader, writer io.Writer) (context.Context, error) {
	_, err := writer.Write([]byte{socks5Version, NoAuth})
	return ctx, err
}

// UserPassAuthenticator is used to handle username/password based
// authentication
type UserPassAuthenticator struct {
	Credentials CredentialStore
}

func (a UserPassAuthenticator) GetCode() uint8 {
	return UserPassAuth
}

func (a UserPassAuthenticator) Authenticate(ctx context.Context, reader io.Reader, writer io.Writer) (context.Context, error) {
	// Tell the client to use user/pass auth
	if _, err := writer.Write([]byte{socks5Version, UserPassAuth}); err != nil {
		return ctx, err
	}

	// Get the version and username length
	header := []byte{0, 0}
	if _, err := io.ReadAtLeast(reader, header, 2); err != nil {
		return ctx, err
	}

	// Ensure we are compatible
	if header[0] != userAuthVersion {
		return ctx, fmt.Errorf("unsupported auth version: %v", header[0])
	}

	// Get the user name
	userLen := int(header[1])
	user := make([]byte, userLen)
	if _, err := io.ReadAtLeast(reader, user, userLen); err != nil {
		return ctx, err
	}

	// Get the password length
	if _, err := reader.Read(header[:1]); err != nil {
		return ctx, err
	}

	// Get the password
	passLen := int(header[0])
	pass := make([]byte, passLen)
	if _, err := io.ReadAtLeast(reader, pass, passLen); err != nil {
		return ctx, err
	}

	// Verify the password
	ctx, isValid := a.Credentials.Valid(ctx, string(user), string(pass))
	if isValid {
		if _, err := writer.Write([]byte{userAuthVersion, authSuccess}); err != nil {
			return ctx, err
		}
	} else {
		if _, err := writer.Write([]byte{userAuthVersion, authFailure}); err != nil {
			return ctx, err
		}
		return ctx, UserAuthFailed
	}

	// Done
	return ctx, nil
}

// Authenticate is used to handle connection authentication
func (s *Server) Authenticate(ctx context.Context, conn io.Writer, bufConn io.Reader) (context.Context, uint8, error) {
	// Read the version byte
	version := []byte{0}
	if _, err := bufConn.Read(version); err != nil {
		return ctx, 0, fmt.Errorf("[ERR] socks: Failed to get version byte: %v", err)
	}

	// Ensure we are compatible
	if version[0] != socks5Version {
		err := fmt.Errorf("unsupported SOCKS version: %v", version)
		return ctx, 0, fmt.Errorf("[ERR] socks: %v", err)
	}

	// Get the methods
	methods, err := readMethods(bufConn)
	if err != nil {
		return ctx, 0, fmt.Errorf("failed to get auth methods: %v", err)
	}

	// Select a usable method
	for i := range methods {
		method := methods[i]
		authenticator, found := s.authMethods[method]
		if !found {
			continue
		}
		ctx, err := authenticator.Authenticate(ctx, bufConn, conn)
		if err != nil {
			return ctx, 0, err
		}
		return ctx, method, err
	}

	// No usable method found
	return ctx, 0, noAcceptableAuth(conn)
}

// noAcceptableAuth is used to handle when we have no eligible
// authentication mechanism
func noAcceptableAuth(conn io.Writer) error {
	_, _ = conn.Write([]byte{socks5Version, noAcceptable})
	return NoSupportedAuth
}

// readMethods is used to read the number of methods
// and proceeding auth methods
func readMethods(r io.Reader) ([]byte, error) {
	header := []byte{0}
	if _, err := r.Read(header); err != nil {
		return nil, err
	}

	numMethods := int(header[0])
	methods := make([]byte, numMethods)
	_, err := io.ReadAtLeast(r, methods, numMethods)
	return methods, err
}
