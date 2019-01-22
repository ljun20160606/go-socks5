package socks5

import (
	"bytes"
	"context"
	"testing"
)

func TestNoAuth(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{1, NoAuth})
	var resp bytes.Buffer

	s, _ := New(&Config{})
	ctx := context.Background()

	ctx, authMethod, err := s.authenticate(ctx, &resp, req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if authMethod != NoAuth {
		t.Fatal("Invalid AuthMethod")
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{socks5Version, NoAuth}) {
		t.Fatalf("bad: %v", out)
	}
}

func TestPasswordAuth_Valid(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{2, NoAuth, UserPassAuth})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	var resp bytes.Buffer

	cred := StaticCredentials{
		"foo": "bar",
	}

	cator := UserPassAuthenticator{Credentials: cred}

	s, _ := New(&Config{AuthMethods: []Authenticator{cator}})
	ctx := context.Background()

	ctx, authMethod, err := s.authenticate(ctx, &resp, req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if authMethod != UserPassAuth {
		t.Fatal("Invalid AuthMethod")
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{socks5Version, UserPassAuth, 1, authSuccess}) {
		t.Fatalf("bad: %v", out)
	}
}

func TestPasswordAuth_Invalid(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{2, NoAuth, UserPassAuth})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'z'})
	var resp bytes.Buffer

	cred := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: cred}
	s, _ := New(&Config{AuthMethods: []Authenticator{cator}})
	ctx := context.Background()

	ctx, authMethod, err := s.authenticate(ctx, &resp, req)
	if err != UserAuthFailed {
		t.Fatalf("err: %v", err)
	}

	if authMethod != NoAuth {
		t.Fatal("Invalid AuthMethod")
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{socks5Version, UserPassAuth, 1, authFailure}) {
		t.Fatalf("bad: %v", out)
	}
}

func TestNoSupportedAuth(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{1, NoAuth})
	var resp bytes.Buffer

	cred := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: cred}

	s, _ := New(&Config{AuthMethods: []Authenticator{cator}})
	ctx := context.Background()

	ctx, authMethod, err := s.authenticate(ctx, &resp, req)
	if err != NoSupportedAuth {
		t.Fatalf("err: %v", err)
	}

	if authMethod != NoAuth {
		t.Fatal("Invalid AuthMethod")
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{socks5Version, noAcceptable}) {
		t.Fatalf("bad: %v", out)
	}
}
