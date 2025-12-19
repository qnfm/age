module filippo.io/age

go 1.24.0

toolchain go1.24.5

require (
	filippo.io/edwards25519 v1.1.0
	golang.org/x/crypto v0.46.0
	golang.org/x/term v0.38.0
)

require (
	github.com/cloudflare/circl v1.6.1
	golang.org/x/sys v0.39.0 // indirect
)

replace github.com/cloudflare/circl => ../circl
