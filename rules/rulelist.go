// (c) Copyright 2016 Hewlett Packard Enterprise Development LP
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rules

import "github.com/securego/gosec"

// RuleDefinition contains the description of a rule and a mechanism to
// create it.
type RuleDefinition struct {
	ID          string
	Description string
	Create      gosec.RuleBuilder
}

// RuleList is a mapping of rule ID's to rule definitions
type RuleList map[string]RuleDefinition

// Builders returns all the create methods for a given rule list
func (rl RuleList) Builders() map[string]gosec.RuleBuilder {
	builders := make(map[string]gosec.RuleBuilder)
	for _, def := range rl {
		builders[def.ID] = def.Create
	}
	return builders
}

// RuleFilter can be used to include or exclude a rule depending on the return
// value of the function
type RuleFilter func(string) bool

// NewRuleFilter is a closure that will include/exclude the rule ID's based on
// the supplied boolean value.
func NewRuleFilter(action bool, ruleIDs ...string) RuleFilter {
	rulelist := make(map[string]bool)
	for _, rule := range ruleIDs {
		rulelist[rule] = true
	}
	return func(rule string) bool {
		if _, found := rulelist[rule]; found {
			return action
		}
		return !action
	}
}

// Generate the list of rules to use
func Generate(filters ...RuleFilter) RuleList {
	rules := []RuleDefinition{
		// misc
		{"hardcreds", "Look for hardcoded credentials", NewHardcodedCredentials},
		{"bind-interfaces", "Bind to all interfaces", NewBindsToAllNetworkInterfaces},
		{"unsafe-block", "Audit the use of unsafe block", NewUsingUnsafe},
		{"error-check", "Audit errors not checked", NewNoErrorCheck},
		{"math-audit", "Audit the use of big.Exp function", NewUsingBigExp},
		{"insecure-ssh-key", "Audit the use of ssh.InsecureIgnoreHostKey function", NewSSHHostKey},
		{"taint-http", "Url provided to HTTP request as taint input", NewSSRFCheck},

		// injection
		{"sql-format-string", "SQL query construction using format string", NewSQLStrFormat},
		{"sql-string-concat", "SQL query construction using string concatenation", NewSQLStrConcat},
		{"unescaped-html-data", "Use of unescaped data in HTML templates", NewTemplateCheck},
		{"cmd-exec", "Audit use of command execution", NewSubproc},

		// filesystem
		{"dir-perm", "Poor file permissions used when creating a directory", NewMkdirPerms},
		{"poor-chmod", "Poor file permissions used when creation file or using chmod", NewFilePerms},
		{"predict-path", "Creating tempfile using a predictable path", NewBadTempFile},
		{"taint-file-path", "File path provided as taint input", NewReadFile},
		{"file-traverse", "File path traversal when extracting zip archive", NewArchive},

		// crypto
		{"insecure-lib", "Detect the usage of DES, RC4, MD5 or SHA1", NewUsesWeakCryptography},
		{"bad-tls", "Look for bad TLS connection settings", NewIntermediateTLSCheck},
		{"min-key-rsa", "Ensure minimum RSA key length of 2048 bits", NewWeakKeyStrength},
		{"insecure-rand", "Insecure random number source (rand)", NewWeakRandCheck},

		// blacklist
		{"blacklist-md5", "Import blacklist: crypto/md5", NewBlacklistedImportMD5},
		{"blacklist-des", "Import blacklist: crypto/des", NewBlacklistedImportDES},
		{"blacklist-rc4", "Import blacklist: crypto/rc4", NewBlacklistedImportRC4},
		{"blacklist-http-cgi", "Import blacklist: net/http/cgi", NewBlacklistedImportCGI},
		{"blacklist-sha1", "Import blacklist: crypto/sha1", NewBlacklistedImportSHA1},
	}

	ruleMap := make(map[string]RuleDefinition)

RULES:
	for _, rule := range rules {
		for _, filter := range filters {
			if filter(rule.ID) {
				continue RULES
			}
		}
		ruleMap[rule.ID] = rule
	}
	return ruleMap
}
