module filippo.io/age

go 1.18

require (
	filippo.io/edwards25519 v1.0.0
	golang.org/x/crypto v0.8.0
	golang.org/x/term v0.7.0
)

require (
	github.com/cloudflare/circl v1.3.2
	golang.org/x/sys v0.7.0 // indirect
)

replace github.com/cloudflare/circl => ..\pufferffish\circl
