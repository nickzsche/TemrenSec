# Harici araç adaptörleri

`scanner.ExternalToolScanner` (pkg/scanner/external_tool.go) herhangi bir dış
ikiliyi `sandbox.Run` ile (zaman/çıktı sınırlı, temiz env) çalıştırıp stdout'u
`[]scanner.Finding`'e çevirir. İkili PATH'te yoksa tarayıcı sessizce atlanır.

## Örnek: portscan

```go
func NewPortscanScanner() scanner.Scanner {
	return &scanner.ExternalToolScanner{
		ScannerName: "portscan",
		Binary:      "portscan",
		Args:        func(t string) []string { return []string{"-json", t} },
		Parse: func(out, target string) []scanner.Finding {
			var f []scanner.Finding
			for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
				if line == "" { continue }
				f = append(f, scanner.Finding{
					Title: "Open port: " + line, Severity: scanner.SeverityInfo,
					Confidence: scanner.ConfidenceHigh, Evidence: line,
				})
			}
			return f
		},
		Timeout: 2 * time.Minute,
	}
}
```

`pkg/scanner/registry.go` → `AllScanners()` içine `NewPortscanScanner()` ekleyin.
Aynı desen `github.com/nickzsche/{portscan,sqliprobe,dirbrute}` için geçerlidir
(ya da bu repolar kendi `Scanner` adaptörünü Go modülü olarak sunduğunda doğrudan import edin).
