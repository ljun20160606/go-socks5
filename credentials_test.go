package socks5

import (
	"context"
	"testing"
)

func TestStaticCredentials(t *testing.T) {
	creds := StaticCredentials{
		"foo": "bar",
		"baz": "",
	}

	ctx := context.Background()

	ctx, isValid := creds.Valid(ctx, "foo", "bar")
	if !isValid {
		t.Fatalf("expect valid")
	}

	ctx, isValid = creds.Valid(ctx, "baz", "")
	if !isValid {
		t.Fatalf("expect valid")
	}

	ctx, isValid = creds.Valid(ctx, "foo", "")
	if isValid {
		t.Fatalf("expect valid")
	}
}
