module github.com/alibkaba/jula-collector

go 1.26.0

require (
	github.com/alibkaba/jula-core v0.0.0
	go.yaml.in/yaml/v4 v4.0.0-rc.6
	golang.org/x/oauth2 v0.37.0
)

require (
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
)

replace github.com/alibkaba/jula-core => ../core
