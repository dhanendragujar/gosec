package rules_test

import (
	"fmt"
	"log"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec"
	"github.com/securego/gosec/rules"
	"github.com/securego/gosec/testutils"
)

type option struct {
	name  gosec.GlobalOption
	value string
}

var _ = Describe("gosec rules", func() {

	var (
		logger    *log.Logger
		config    gosec.Config
		analyzer  *gosec.Analyzer
		runner    func(string, []testutils.CodeSample, ...option)
		buildTags []string
	)

	BeforeEach(func() {
		logger, _ = testutils.NewLogger()
		config = gosec.NewConfig()
		analyzer = gosec.NewAnalyzer(config, logger)
		runner = func(rule string, samples []testutils.CodeSample, options ...option) {
			for _, o := range options {
				config.SetGlobal(o.name, o.value)
			}
			analyzer.LoadRules(rules.Generate(rules.NewRuleFilter(false, rule)).Builders())
			for n, sample := range samples {
				analyzer.Reset()
				pkg := testutils.NewTestPackage()
				defer pkg.Close()
				for i, code := range sample.Code {
					pkg.AddFile(fmt.Sprintf("sample_%d_%d.go", n, i), code)
				}
				err := pkg.Build()
				Expect(err).ShouldNot(HaveOccurred())
				err = analyzer.Process(buildTags, pkg.Path)
				Expect(err).ShouldNot(HaveOccurred())
				issues, _, _ := analyzer.Report()
				if len(issues) != sample.Errors {
					fmt.Println(sample.Code)
				}
				Expect(issues).Should(HaveLen(sample.Errors))
			}
		}
	})

	Context("report correct errors for all samples", func() {
		It("should detect hardcoded credentials", func() {
			runner("hardcreds", testutils.SampleCodehardcreds)
		})

		It("should detect binding to all network interfaces", func() {
			runner("bind-interfaces", testutils.SampleCodebind-interfaces)
		})

		It("should use of unsafe block", func() {
			runner("unsafe-block", testutils.SampleCodeunsafe-block)
		})

		It("should detect errors not being checked", func() {
			runner("error-check", testutils.SampleCodeerror-check)
		})

		It("should detect errors not being checked in audit mode", func() {
			runner("error-check", testutils.SampleCodeerror-checkAudit, option{name: gosec.Audit, value: "enabled"})
		})

		It("should detect of big.Exp function", func() {
			runner("math-audit", testutils.SampleCodemath-audit)
		})

		It("should detect of ssh.InsecureIgnoreHostKey function", func() {
			runner("insecure-ssh-key", testutils.SampleCodeinsecure-ssh-key)
		})

		It("should detect ssrf via http requests with variable url", func() {
			runner("taint-http", testutils.SampleCodetaint-http)
		})

		It("should detect sql injection via format strings", func() {
			runner("sql-format-string", testutils.SampleCodesql-format-string)
		})

		It("should detect sql injection via string concatenation", func() {
			runner("sql-string-concat", testutils.SampleCodesql-string-concat)
		})

		It("should detect unescaped html in templates", func() {
			runner("unescaped-html-data", testutils.SampleCodeunescaped-html-data)
		})

		It("should detect command execution", func() {
			runner("cmd-exec", testutils.SampleCodecmd-exec)
		})

		It("should detect poor file permissions on mkdir", func() {
			runner("dir-perm", testutils.SampleCodedir-perm)
		})

		It("should detect poor permissions when creating or chmod a file", func() {
			runner("poor-chmod", testutils.SampleCodepoor-chmod)
		})

		It("should detect insecure temp file creation", func() {
			runner("predict-path", testutils.SampleCodepredict-path)
		})

		It("should detect file path provided as taint input", func() {
			runner("taint-file-path", testutils.SampleCodetaint-file-path)
		})

		It("should detect file path traversal when extracting zip archive", func() {
			runner("file-traverse", testutils.SampleCodefile-traverse)
		})

		It("should detect weak crypto algorithms", func() {
			runner("insecure-lib", testutils.SampleCodeinsecure-lib)
		})

		It("should detect weak crypto algorithms", func() {
			runner("insecure-lib", testutils.SampleCodeinsecure-libb)
		})

		It("should find insecure tls settings", func() {
			runner("bad-tls", testutils.SampleCodebad-tls)
		})

		It("should detect weak creation of weak rsa keys", func() {
			runner("min-key-rsa", testutils.SampleCodemin-key-rsa)
		})

		It("should find non cryptographically secure random number sources", func() {
			runner("insecure-rand", testutils.SampleCodeinsecure-rand)
		})

		It("should detect blacklisted imports - MD5", func() {
			runner("blacklist-md5", testutils.SampleCodeblacklist-md5)
		})

		It("should detect blacklisted imports - DES", func() {
			runner("blacklist-des", testutils.SampleCodeblacklist-des)
		})

		It("should detect blacklisted imports - RC4", func() {
			runner("blacklist-rc4", testutils.SampleCodeblacklist-rc4)
		})

		It("should detect blacklisted imports - CGI (httpoxy)", func() {
			runner("blacklist-http-cgi", testutils.SampleCodeblacklist-http-cgi)
		})
		It("should detect blacklisted imports - SHA1", func() {
			runner("blacklist-sha1", testutils.SampleCodeblacklist-sha1)
		})

	})

})
