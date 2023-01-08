module github.com/TomCN0803/taat-lib

go 1.19

require (
	github.com/cloudflare/bn256 v0.0.0-20220804214613-39fbc7d184f0
	github.com/stretchr/testify v1.8.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.5.0 // indirect
	golang.org/x/sys v0.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace golang.org/x/crypto v0.4.0 => github.com/TomCN0803/crypto v0.0.0-20230104163823-164becd28591
