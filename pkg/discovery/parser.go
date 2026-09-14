package discovery

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ParseDirectory walks a directory tree and parses source files for API endpoints.
func ParseDirectory(root string) ([]APIEndpoint, error) {
	var endpoints []APIEndpoint
	seen := make(map[string]bool)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".go":
			eps := parseGoFile(path)
			for _, ep := range eps {
				key := ep.Method + " " + ep.Path
				if !seen[key] {
					seen[key] = true
					endpoints = append(endpoints, ep)
				}
			}
		case ".js", ".ts", ".jsx", ".tsx":
			eps := parseJSFile(path)
			for _, ep := range eps {
				key := ep.Method + " " + ep.Path
				if !seen[key] {
					seen[key] = true
					endpoints = append(endpoints, ep)
				}
			}
		case ".py":
			eps := parsePythonFile(path)
			for _, ep := range eps {
				key := ep.Method + " " + ep.Path
				if !seen[key] {
					seen[key] = true
					endpoints = append(endpoints, ep)
				}
			}
		case ".java":
			eps := parseJavaFile(path)
			for _, ep := range eps {
				key := ep.Method + " " + ep.Path
				if !seen[key] {
					seen[key] = true
					endpoints = append(endpoints, ep)
				}
			}
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walking directory: %w", err)
	}

	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Path != endpoints[j].Path {
			return endpoints[i].Path < endpoints[j].Path
		}
		return endpoints[i].Method < endpoints[j].Method
	})

	return endpoints, nil
}

var goPatterns = []*regexp.Regexp{
	regexp.MustCompile(`http\.(HandleFunc|Handle)\(\s*"([^"]+)"`),
	regexp.MustCompile(`\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\(\s*"([^"]+)"`),
}

// Matches .GET("/path", ...), .POST("/path", ...) etc. for gin/echo/fiber
var goMethodPattern = regexp.MustCompile(`\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\(\s*"([^"]+)"`)
// Matches http.HandleFunc("/path", ...) and http.Handle("/path", ...)
var goHandleFuncPattern = regexp.MustCompile(`http\.(HandleFunc|Handle)\(\s*"([^"]+)"`)
// Matches group assignments like g := r.Group("/api")
var goGroupPattern = regexp.MustCompile(`(\w+)\s*:=?\s*\w+\.Group\(\s*"([^"]+)"`)

func parseGoFile(path string) []APIEndpoint {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var endpoints []APIEndpoint
	groups := make(map[string]string)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if matches := goGroupPattern.FindStringSubmatch(line); len(matches) == 3 {
			groups[matches[1]] = matches[2]
		}

		if matches := goMethodPattern.FindStringSubmatch(line); len(matches) == 3 {
			method := matches[1]
			routePath := matches[2]
			ep := APIEndpoint{
				Method:      method,
				Path:        routePath,
				Description: fmt.Sprintf("Discovered from Go source: %s %s", method, routePath),
				Tags:        []string{"go"},
			}
			endpoints = append(endpoints, ep)
		}

		if matches := goHandleFuncPattern.FindStringSubmatch(line); len(matches) == 3 {
			routePath := matches[2]
			ep := APIEndpoint{
				Method:      "GET", // HandleFunc defaults to all methods, but commonly GET
				Path:        routePath,
				Description: fmt.Sprintf("Discovered from Go source: %s", routePath),
				Tags:        []string{"go"},
			}
			endpoints = append(endpoints, ep)
		}
	}

	_ = groups

	return endpoints
}

// Matches app.get("/path", ...), router.get("/path", ...), etc.
var jsMethodPattern = regexp.MustCompile(`(?:app|router|route|Router)\.(get|post|put|delete|patch|head|options)\(\s*['"]([^'"]+)['"]`)
var jsUsePattern = regexp.MustCompile(`(?:app|router)\.(use|all)\(\s*['"]([^'"]+)['"]`)
var nextjsApiPattern = regexp.MustCompile(`(?:export\s+default\s+)?(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(`)

func parseJSFile(path string) []APIEndpoint {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var endpoints []APIEndpoint

	if strings.Contains(path, "/api/") {
		idx := strings.Index(path, "/api/")
		if idx >= 0 {
			apiSubPath := path[idx+5:]
			apiSubPath = strings.TrimSuffix(apiSubPath, "/route.ts")
			apiSubPath = strings.TrimSuffix(apiSubPath, "/route.js")
			apiSubPath = strings.TrimSuffix(apiSubPath, "/route.tsx")
			apiSubPath = strings.TrimSuffix(apiSubPath, "/route.jsx")
			apiSubPath = strings.TrimSuffix(apiSubPath, ".ts")
			apiSubPath = strings.TrimSuffix(apiSubPath, ".js")
			apiSubPath = strings.TrimSuffix(apiSubPath, ".tsx")
			apiSubPath = strings.TrimSuffix(apiSubPath, ".jsx")
			apiSubPath = regexp.MustCompile(`\[([^\]]+)\]`).ReplaceAllString(apiSubPath, `{$1}`)

			if apiSubPath != "" {
				apiPath := "/api/" + apiSubPath
				methods := detectNextjsMethods(path)
				if len(methods) > 0 {
					for _, m := range methods {
						ep := APIEndpoint{
							Method:      m,
							Path:        apiPath,
							Description: fmt.Sprintf("Next.js API route: %s %s", m, apiPath),
							Tags:        []string{"nextjs"},
						}
						endpoints = append(endpoints, ep)
					}
				} else {
					ep := APIEndpoint{
						Method:      "GET",
						Path:        apiPath,
						Description: "Next.js API route: " + apiPath,
						Tags:        []string{"nextjs"},
					}
					endpoints = append(endpoints, ep)
				}
			}
		}
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if matches := jsMethodPattern.FindStringSubmatch(line); len(matches) == 3 {
			method := strings.ToUpper(matches[1])
			routePath := matches[2]
			ep := APIEndpoint{
				Method:      method,
				Path:        routePath,
				Description: fmt.Sprintf("Discovered from JS/TS source: %s %s", method, routePath),
				Tags:        []string{"javascript"},
			}
			endpoints = append(endpoints, ep)
		}

		if matches := jsUsePattern.FindStringSubmatch(line); len(matches) == 3 {
			routePath := matches[2]
			ep := APIEndpoint{
				Method:      "GET",
				Path:        routePath,
				Description: fmt.Sprintf("Discovered from JS/TS middleware: %s", routePath),
				Tags:        []string{"javascript"},
			}
			endpoints = append(endpoints, ep)
		}
	}

	_ = nextjsApiPattern
	return endpoints
}

// detectNextjsMethods reads a file and looks for exported HTTP method functions.
func detectNextjsMethods(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var methods []string
	methodNames := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		for _, m := range methodNames {
			if strings.Contains(line, "export") && (strings.Contains(line, m+"(") || strings.Contains(line, m+" =")) {
				methods = append(methods, m)
			}
		}
	}

	return methods
}

// Matches Flask @app.route("/path") and @app.route("/path", methods=[...])
var flaskRoutePattern = regexp.MustCompile(`@(?:app|application)\.route\(\s*['"]([^'"]+)['"]\s*(?:,\s*methods\s*=\s*\[([^\]]+)\])?`)
// Matches FastAPI @app.get("/path"), @app.post("/path"), etc.
var fastApiMethodPattern = regexp.MustCompile(`@(?:app|application)\.(get|post|put|delete|patch)\(\s*['"]([^'"]+)['"]`)
// Matches Django path("url/", view)
var djangoUrlPattern = regexp.MustCompile(`path\(\s*['"]([^'"]+)['"]`)

func parsePythonFile(path string) []APIEndpoint {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var endpoints []APIEndpoint

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if matches := flaskRoutePattern.FindStringSubmatch(line); len(matches) >= 2 {
			routePath := matches[1]
			methods := []string{"GET"}
			if len(matches) > 2 && matches[2] != "" {
				methodStr := matches[2]
				for _, m := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"} {
					if strings.Contains(strings.ToUpper(methodStr), m) {
						methods = append(methods, m)
					}
				}
				if len(methods) == 0 {
					methods = []string{"GET"}
				}
			}
			for _, m := range methods {
				ep := APIEndpoint{
					Method:      m,
					Path:        routePath,
					Description: fmt.Sprintf("Discovered from Flask source: %s %s", m, routePath),
					Tags:        []string{"flask"},
				}
				endpoints = append(endpoints, ep)
			}
		}

		if matches := fastApiMethodPattern.FindStringSubmatch(line); len(matches) == 3 {
			method := strings.ToUpper(matches[1])
			routePath := matches[2]
			ep := APIEndpoint{
				Method:      method,
				Path:        routePath,
				Description: fmt.Sprintf("Discovered from FastAPI source: %s %s", method, routePath),
				Tags:        []string{"fastapi"},
			}
			endpoints = append(endpoints, ep)
		}

		if matches := djangoUrlPattern.FindStringSubmatch(line); len(matches) == 2 {
			routePath := matches[1]
			if !strings.HasPrefix(routePath, "/") {
				routePath = "/" + routePath
			}
			ep := APIEndpoint{
				Method:      "GET", // Django URL patterns default to GET
				Path:        routePath,
				Description: fmt.Sprintf("Discovered from Django source: %s", routePath),
				Tags:        []string{"django"},
			}
			endpoints = append(endpoints, ep)
		}
	}

	return endpoints
}

// Matches Spring @GetMapping("/path")
var springGetPattern = regexp.MustCompile(`@GetMapping\(\s*(?:"([^"]+)")?(?:\s*,\s*produces\s*=\s*"[^"]*")?\s*\)`)
// Matches Spring @PostMapping("/path")
var springPostPattern = regexp.MustCompile(`@PostMapping\(\s*(?:"([^"]+)")?\s*\)`)
// Matches Spring @PutMapping("/path")
var springPutPattern = regexp.MustCompile(`@PutMapping\(\s*(?:"([^"]+)")?\s*\)`)
// Matches Spring @DeleteMapping("/path")
var springDeletePattern = regexp.MustCompile(`@DeleteMapping\(\s*(?:"([^"]+)")?\s*\)`)
// Matches Spring @PatchMapping("/path")
var springPatchPattern = regexp.MustCompile(`@PatchMapping\(\s*(?:"([^"]+)")?\s*\)`)
// Matches Spring @RequestMapping(value="/path", method=RequestMethod.GET)
var springRequestMappingPattern = regexp.MustCompile(`@RequestMapping\(\s*(?:value\s*=\s*)?(?:"([^"]+)")?(?:\s*,\s*method\s*=\s*(?:RequestMethod\.)?(\w+))?\s*\)`)
// Matches class-level @RequestMapping("/prefix")
var springClassMappingPattern = regexp.MustCompile(`@RequestMapping\(\s*(?:"([^"]+)")?\s*\)`)

func parseJavaFile(path string) []APIEndpoint {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var endpoints []APIEndpoint
	var classPrefix string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if matches := springClassMappingPattern.FindStringSubmatch(line); len(matches) == 2 && matches[1] != "" {
			classPrefix = matches[1]
		}

		if matches := springGetPattern.FindStringSubmatch(line); len(matches) >= 2 {
			routePath := matches[1]
			if routePath == "" {
				routePath = "/"
			}
			ep := APIEndpoint{
				Method:      "GET",
				Path:        joinPaths(classPrefix, routePath),
				Description: fmt.Sprintf("Discovered from Spring source: GET %s", joinPaths(classPrefix, routePath)),
				Tags:        []string{"spring"},
			}
			endpoints = append(endpoints, ep)
		}

		if matches := springPostPattern.FindStringSubmatch(line); len(matches) == 2 {
			routePath := matches[1]
			if routePath == "" {
				routePath = "/"
			}
			ep := APIEndpoint{
				Method:      "POST",
				Path:        joinPaths(classPrefix, routePath),
				Description: fmt.Sprintf("Discovered from Spring source: POST %s", joinPaths(classPrefix, routePath)),
				Tags:        []string{"spring"},
			}
			endpoints = append(endpoints, ep)
		}

		if matches := springPutPattern.FindStringSubmatch(line); len(matches) == 2 {
			routePath := matches[1]
			if routePath == "" {
				routePath = "/"
			}
			ep := APIEndpoint{
				Method:      "PUT",
				Path:        joinPaths(classPrefix, routePath),
				Description: fmt.Sprintf("Discovered from Spring source: PUT %s", joinPaths(classPrefix, routePath)),
				Tags:        []string{"spring"},
			}
			endpoints = append(endpoints, ep)
		}

		if matches := springDeletePattern.FindStringSubmatch(line); len(matches) == 2 {
			routePath := matches[1]
			if routePath == "" {
				routePath = "/"
			}
			ep := APIEndpoint{
				Method:      "DELETE",
				Path:        joinPaths(classPrefix, routePath),
				Description: fmt.Sprintf("Discovered from Spring source: DELETE %s", joinPaths(classPrefix, routePath)),
				Tags:        []string{"spring"},
			}
			endpoints = append(endpoints, ep)
		}

		if matches := springPatchPattern.FindStringSubmatch(line); len(matches) == 2 {
			routePath := matches[1]
			if routePath == "" {
				routePath = "/"
			}
			ep := APIEndpoint{
				Method:      "PATCH",
				Path:        joinPaths(classPrefix, routePath),
				Description: fmt.Sprintf("Discovered from Spring source: PATCH %s", joinPaths(classPrefix, routePath)),
				Tags:        []string{"spring"},
			}
			endpoints = append(endpoints, ep)
		}

		if matches := springRequestMappingPattern.FindStringSubmatch(line); len(matches) >= 2 {
			routePath := matches[1]
			if routePath == "" {
				routePath = "/"
			}
			method := "GET"
			if len(matches) > 2 && matches[2] != "" {
				method = matches[2]
			}
			ep := APIEndpoint{
				Method:      method,
				Path:        joinPaths(classPrefix, routePath),
				Description: fmt.Sprintf("Discovered from Spring source: %s %s", method, joinPaths(classPrefix, routePath)),
				Tags:        []string{"spring"},
			}
			endpoints = append(endpoints, ep)
		}
	}

	return endpoints
}

func joinPaths(prefix, path string) string {
	if prefix == "" {
		return path
	}
	prefix = strings.TrimRight(prefix, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return prefix + path
}