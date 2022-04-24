module filippo.io/age

go 1.23.0

toolchain go1.24.5

require (
	filippo.io/edwards25519 v1.1.0
	golang.org/x/crypto v0.40.0
	golang.org/x/term v0.33.0
)

require github.com/lukechampine/fastxor v0.0.0-20210322201628-b664bed5a5cc

require (
	github.com/cloudflare/circl v1.6.1
	golang.org/x/sys v0.34.0 // indirect
)

replace github.com/cloudflare/circl => ../circl
