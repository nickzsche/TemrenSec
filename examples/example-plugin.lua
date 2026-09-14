-- temren plugin example: a tiny LUA scanner that flags responses still serving
-- "Powered by" / "X-Generator" fingerprints, since they help attackers map versions.
--
-- Save this file under plugins/ and run:
--   temren scan --target https://example.com --plugin plugins/fingerprint.lua
--
-- Lua API:
--   temren.http_get(url) -> {status, body, headers}
--   temren.finding{title, severity, description, ...}

local target = temren.target

local resp, err = temren.http_get(target)
if err ~= nil then
  return
end

local h = resp.headers or {}
local banners = {
  ["X-Powered-By"]  = "X-Powered-By",
  ["X-Generator"]   = "X-Generator",
  ["X-AspNet-Version"] = "ASP.NET version",
}
for header, label in pairs(banners) do
  if h[header] ~= nil then
    temren.finding{
      title       = "Server fingerprint leaked: " .. label,
      description = "Response advertises " .. h[header] .. ". Strip from your reverse proxy.",
      severity    = "LOW",
      scanner     = "lua/fingerprint",
      owasp       = "A05:2021-Security Misconfiguration",
      cvss        = 3.7,
      evidence    = header .. ": " .. h[header],
    }
  end
end
