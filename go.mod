module filippo.io/age

go 1.18

require (
	filippo.io/edwards25519 v1.0.0
	golang.org/x/crypto v0.12.0
	golang.org/x/term v0.12.0
)

require github.com/lukechampine/fastxor v0.0.0-20210322201628-b664bed5a5cc

require (
	github.com/cloudflare/circl v1.3.3
	golang.org/x/sys v0.12.0 // indirect
)

replace github.com/cloudflare/circl => ..\pufferffish\circl
