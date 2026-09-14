package scanner

// AllScanners returns every Scanner implementation that ships in this package.
// This is the single source of truth for "every check Temren knows about" so
// callers (CLI, worker, embedded server) don't have to keep their own list in
// sync with new scanners.
//
// Order: roughly grouped by category for readable output; severity is irrelevant
// to ordering since the engine runs them in parallel anyway.
func AllScanners() []Scanner {
	return []Scanner{
		// Injection family
		NewSQLiScanner(),
		NewXSSScanner(),
		NewCommandInjectionScanner(),
		NewSSTIScanner(),
		NewAdvancedTemplateInjectionScanner(),
		NewSSIInjectionScanner(),
		NewLDAPInjectionScanner(),
		NewXPathInjectionScanner(),
		NewNoSQLInjectionScanner(),
		NewEmailHeaderInjectionScanner(),

		// SSRF / cloud
		NewSSRFScanner(),
		NewSSRFCloudMetadataScanner(),

		// Auth / access control
		NewIDORScanner(),
		NewJWTScanner(),
		NewJWTKeyConfusionScanner(),
		NewJWTJKUInjectionScanner(),
		NewOAuthMisconfigScanner(),
		NewSAMLEndpointScanner(),
		NewSCIMEnumerationScanner(),
		NewAuthFailureScanner(),
		NewHTTPMethodOverrideScanner(),
		NewMassAssignmentScanner(),
		NewPasswordResetEnumScanner(),
		NewServerSidePrototypePollutionScanner(),
		NewCSRFScanner(),
		NewSessionFixationScanner(),
		NewDefaultCredentialsScanner(),

		// Deserialization / supply chain
		NewDeserializationScanner(),

		// CORS / headers / cookies
		NewCORSScanner(),
		NewCORSPreflightScanner(),
		NewSecurityHeadersScanner(),
		NewHSTSPreloadScanner(),
		NewClickjackingScanner(),
		NewCSPBypassScanner(),
		NewETagLeakScanner(),
		NewServerFingerprintScanner(),

		// HTTP plumbing
		NewRequestSmugglingScanner(),
		NewCachePoisoningScanner(),
		NewWebCacheDeceptionScanner(),
		NewHostHeaderInjectionScanner(),
		NewHTTPParameterPollutionScanner(),
		NewNginxAliasTraversalScanner(),
		NewOpenRedirectScanner(),
		NewOpenRedirectPathScanner(),
		NewContentTypeConfusionScanner(),
		NewJSONPCallbackScanner(),

		// XML / file processing
		NewXXEScanner(),
		NewFileUploadBypassScanner(""),

		// Path / file disclosure
		NewPathTraversalScanner(),
		NewBackupFileScanner(),
		NewExposedEndpointsScanner(),

		// Crypto / TLS / email auth
		NewTLSAuditScanner(),
		NewEmailAuthScanner(),
		NewPaddingOracleScanner(),

		// GraphQL surface
		NewGraphQLScanner(),
		NewGraphQLBatchingScanner(),
		NewGraphQLFieldSuggestionScanner(),
		NewGraphQLCSRFScanner(),

		// API / framework / dev-tool exposure
		NewAPISecurityScanner("", false),
		NewWebDAVScanner(),
		NewGRPCReflectionScanner(),
		NewStorybookExposureScanner(),
		NewSwaggerScanner(),
		NewSubresourceIntegrityScanner(),
		NewWellKnownScanner(),
		NewWebSocketOriginScanner(),
		NewPostMessageScanner(),

		// Recon / discovery
		NewSubdomainEnumerator(),
		NewParameterMiner(),
		NewDirectoryBruteForceScanner(),
		NewTechnologyDetector(),
		NewWAFDetector(),
		NewHoneypotDetector(),
		NewDanglingDNSScanner(),
		NewSubdomainTakeoverScanner(),
		NewDSNLeakScanner(),
		NewCloudLeakScanner(),
		NewPrototypePollutionScanner(),

		// Race / timing
		NewRaceConditionScanner(),

		// Misc misconfig
		NewErrorHandlingScanner(),
		NewLoggingMonitoringScanner(),
		NewInsecureDesignScanner(),
		NewSoftwareSupplyChainScanner(),
		NewVulnerableComponentsScanner(),
		NewFormParameterScanner(),
		NewSecretScanner(),
		NewLLMScanner(),
		NewSourceMapLeakScanner(),
		NewTemplateScanner(),
	}
}

// EnabledScanners filters AllScanners() by a name set. Empty set → all.
// Names are matched against Scanner.Name() case-insensitively, partial substring.
func EnabledScanners(enabled []string) []Scanner {
	all := AllScanners()
	if len(enabled) == 0 {
		return all
	}
	out := make([]Scanner, 0, len(enabled))
	for _, s := range all {
		name := lowerEN(s.Name())
		for _, want := range enabled {
			if containsEN(name, lowerEN(want)) {
				out = append(out, s)
				break
			}
		}
	}
	return out
}

// Tiny ASCII-only helpers — avoid importing "strings" just for this and to keep
// behaviour identical regardless of locale.
func lowerEN(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func containsEN(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
