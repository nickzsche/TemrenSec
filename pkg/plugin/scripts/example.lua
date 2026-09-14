-- Example plugin: Custom Header Check
-- Place in ~/.temren/plugins/ or use --plugins-dir flag
--
-- Required functions:
--   name() - returns plugin name as string
--   scan(target, response_body, response_headers) - returns table of findings

function name()
    return "Custom Header Check"
end

function scan(target, response_body, response_headers)
    local findings = {}

    -- Check for missing X-Frame-Options header
    if not response_headers["X-Frame-Options"] then
        table.insert(findings, {
            title = "Missing X-Frame-Options",
            severity = "MEDIUM",
            description = "Clickjacking protection missing. The X-Frame-Options header prevents the page from being embedded in frames, protecting against clickjacking attacks.",
            url = target
        })
    end

    -- Check for missing X-Content-Type-Options header
    if not response_headers["X-Content-Type-Options"] then
        table.insert(findings, {
            title = "Missing X-Content-Type-Options",
            severity = "LOW",
            description = "MIME type sniffing not disabled. Without this header, browsers may interpret responses as different content types.",
            url = target
        })
    end

    -- Check for missing Content-Security-Policy header
    if not response_headers["Content-Security-Policy"] then
        table.insert(findings, {
            title = "Missing Content-Security-Policy",
            severity = "MEDIUM",
            description = "Content Security Policy not configured. CSP helps prevent XSS and data injection attacks.",
            url = target
        })
    end

    -- Check for information disclosure in Server header
    local server = response_headers["Server"]
    if server then
        if string.find(string.lower(server), "apache") or
           string.find(string.lower(server), "nginx") or
           string.find(string.lower(server), "php") then
            table.insert(findings, {
                title = "Server Version Disclosure",
                severity = "LOW",
                description = "Server header reveals technology: " .. server,
                url = target,
                evidence = "Server: " .. server
            })
        end
    end

    return findings
end
