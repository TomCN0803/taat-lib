module github.com/TomCN0803/taat-lib

go 1.19

require (
	github.com/stretchr/testify v1.8.1
	golang.org/x/crypto v0.4.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace golang.org/x/crypto v0.4.0 => github.com/TomCN0803/crypto v0.0.0-20230104163823-164becd28591
