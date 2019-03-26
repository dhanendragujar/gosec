
# gosec

Inspects source code for security problems by scanning the Go AST.

## License

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License [here](http://www.apache.org/licenses/LICENSE-2.0).

## Install

### CI Installation

```bash
# binary will be $GOPATH/bin/gosec
curl -sfL https://raw.githubusercontent.com/dhanendragujar/gosec/master/install.sh | sh -s -- -b $GOPATH/bin vX.Y.Z

# or install it into ./bin/
curl -sfL https://raw.githubusercontent.com/dhanendragujar/gosec/master/install.sh | sh -s vX.Y.Z

# In alpine linux (as it does not come with curl by default)
wget -O - -q https://raw.githubusercontent.com/dhanendragujar/gosec/master/install.sh | sh -s vX.Y.Z

gosec --help
```

### Local Installation

`$ go get github.com/dhanendragujar/gosec/cmd/gosec/...`

## Usage

Gosec can be configured to only run a subset of rules, to exclude certain file
paths, and produce reports in different formats. By default all rules will be
run against the supplied input files. To recursively scan from the current
directory you can supply './...' as the input argument.

### Selecting rules

By default gosec will run all rules against the supplied file paths and will perform Taint Analysis on the code to check whether the user input is being validated or not. It is however possible to select a subset of rules to run via the '-include=' flag,
or to specify a set of rules to explicitly exclude using the '-exclude=' flag. To disable Taint Analysis specify '--notaintanalysis' flag.

### Available rules

- hardcreds: Look for hard coded credentials
- bind-interfaces: Bind to all interfaces
- unsafe-block: Audit the use of unsafe block
- error-check: Audit errors not checked
- math-audit: Audit the use of math/big.Int.Exp
- insecure-ssh-key: Audit the use of ssh.InsecureIgnoreHostKey
- taint-http: Url provided to HTTP request as taint input
- sql-format-string: SQL query construction using format string
- sql-string-concat: SQL query construction using string concatenation
- unescapted-html-data: Use of unescaped data in HTML templates
- cmd-exec: Audit use of command execution
- dir-perm: Poor file permissions used when creating a directory
- poor-chmod: Poor file permissions used with chmod
- predict-path: Creating tempfile using a predictable path
- taint-file-path: File path provided as taint input
- file-traverse: File traversal when extracting zip archive
- insecure-lib: Detect the usage of DES, RC4, MD5 or SHA1
- bad-tls: Look for bad TLS connection settings
- min-key-rsa: Ensure minimum RSA key length of 2048 bits
- insecure-rand: Insecure random number source (rand)
- blacklist-md5: Import blacklist: crypto/md5
- blacklist-des: Import blacklist: crypto/des
- blacklist-rc4: Import blacklist: crypto/rc4
- blacklist-http-cgi: Import blacklist: net/http/cgi
- blacklist-sha1: Import blacklist: crypto/sha1

```bash
# Run a specific set of rules
$ gosec -include=hardcreds, bind-interfaces, insecure-ssh-key ./...

# Run everything except for rule G303
$ gosec -exclude=blacklist-sha1 ./...
```

### Configuration

A number of global settings can be provided in a configuration file as follows:

```JSON
{
    "global": {
        "nosec": "enabled",
        "audit": "enabled"
    }
}
```

- `nosec`: this setting will overwrite all `#nosec` directives defined throughout the code base
- `audit`: runs in audit mode which enables addition checks that for normal code analysis might be too nosy

```bash
# Run with a global configuration file
$ goesc -conf config.json .
```

### Excluding files

gosec will ignore dependencies in your vendor directory any files
that are not considered build artifacts by the compiler (so test files).

### Annotating code

As with all automated detection tools there will be cases of false positives. In cases where gosec reports a failure that has been manually verified as being safe it is possible to annotate the code with a '#nosec' comment.

The annotation causes gosec to stop processing any further nodes within the
AST so can apply to a whole block or more granularly to a single expression.

```go

import "md5" // #nosec


func main(){

    /* #nosec */
    if x > y {
        h := md5.New() // this will also be ignored
    }

}

```

When a specific false positive has been identified and verified as safe, you may wish to suppress only that single rule (or a specific set of rules) within a section of code, while continuing to scan for other problems. To do this, you can list the rule(s) to be suppressed within the `#nosec` annotation, e.g: `/* #nosec G401 */` or `// #nosec G201 G202 G203 `

In some cases you may also want to revisit places where #nosec annotations
have been used. To run the scanner and ignore any #nosec annotations you
can do the following:

```bash
gosec -nosec=true ./...
```

### Build tags

gosec is able to pass your [Go build tags](https://golang.org/pkg/go/build/) to the analyzer.
They can be provided as a comma separated list as follows:

```bash
gosec -tag debug,ignore ./...
```

### Output formats

gosec currently supports text, json, yaml, csv and JUnit XML output formats. By default
results will be reported to stdout, but can also be written to an output
file. The output format is controlled by the '-fmt' flag, and the output file is controlled by the '-out' flag as follows:

```bash
# Write output in json format to results.json
$ gosec -fmt=json -out=results.json *.go
```

## Development

### Prerequisites

Install dep according to the instructions here: https://github.com/golang/dep
Install the latest version of golint:

```bash
go get -u golang.org/x/lint/golint
```

### Build

```bash
make
```

### Tests

```bash
make test
```

### Release Build

Make sure you have installed the [goreleaser](https://github.com/goreleaser/goreleaser) tool and then you can release gosec as follows:

```bash
git tag 1.0.0
export GITHUB_TOKEN=<YOUR GITHUB TOKEN>
make release
```

The released version of the tool is available in the `dist` folder. The build information should be displayed in the usage text.

```bash
./dist/darwin_amd64/gosec -h
gosec  - Golang security checker

gosec analyzes Go source code to look for common programming mistakes that
can lead to security problems.

VERSION: 1.0.0
GIT TAG: 1.0.0
BUILD DATE: 2018-04-27T12:41:38Z
```

Note that all released archives are also uploaded to GitHub.

### Docker image

You can build the docker image as follows:

```bash
make image
```

You can run the `gosec` tool in a container against your local Go project. You just have to mount the project in the
`GOPATH` of the container:

```bash
docker run -it -v $GOPATH/src/<YOUR PROJECT PATH>:/go/src/<YOUR PROJECT PATH> dhanendragujar/gosec ./...
```

### Generate TLS rule

The configuration of TLS rule can be generated from [Mozilla's TLS ciphers recommendation](https://statics.tls.security.mozilla.org/server-side-tls-conf.json).

First you need to install the generator tool:

```bash
go get github.com/dhanendragujar/gosec/cmd/tlsconfig/...
```

You can invoke now the `go generate` in the root of the project:

```bash
go generate ./...
```

This will generate the `rules/tls_config.go` file with will contain the current ciphers recommendation from Mozilla.
