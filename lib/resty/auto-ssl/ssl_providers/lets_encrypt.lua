local _M = {}

local acme_rate_limit = require "resty.auto-ssl.utils.acme_rate_limit"
local shell_execute = require "resty.auto-ssl.utils.shell_execute"

-- Parse a "retry after <ISO8601 UTC>" hint out of a Let's Encrypt rate-limit
-- message and return how many seconds from now that is, or nil if absent or
-- implausible. LE includes this for several limits (e.g. certificates per
-- registered domain), letting us back off exactly as long as it asks.
local function parse_retry_after(text)
  local y, mon, d, h, mi, s = string.match(text, "retry after (%d%d%d%d)-(%d%d)-(%d%d)[T ](%d%d):(%d%d):(%d%d)")
  if not y then
    return nil
  end

  -- os.time treats the table as local time; LE timestamps are UTC, so add the
  -- local-to-UTC offset to get a correct epoch.
  local utc_offset = os.difftime(os.time(), os.time(os.date("!*t")))
  local target = os.time({
    year = tonumber(y), month = tonumber(mon), day = tonumber(d),
    hour = tonumber(h), min = tonumber(mi), sec = tonumber(s), isdst = false,
  }) + utc_offset

  local seconds = target - ngx.now()
  if seconds < 60 then
    return nil
  elseif seconds > 7 * 24 * 60 * 60 then
    return 7 * 24 * 60 * 60
  end

  return seconds
end

function _M.issue_cert(auto_ssl_instance, domain)
  assert(type(domain) == "string", "domain must be a string")

  -- Enforce the account-wide Let's Encrypt order rate limit before creating an
  -- order. Both issuance and renewal funnel through here, so this caps the
  -- combined order rate against ACME's limits. Callers treat this error
  -- specially (renewal defers without deleting; issuance serves the fallback).
  if not acme_rate_limit.allow(auto_ssl_instance:get("max_acme_orders"), auto_ssl_instance:get("acme_order_period")) then
    return nil, "acme rate limit reached"
  end

  local lua_root = auto_ssl_instance.lua_root
  assert(type(lua_root) == "string", "lua_root must be a string")

  local base_dir = auto_ssl_instance:get("dir")
  assert(type(base_dir) == "string", "dir must be a string")

  local hook_port = auto_ssl_instance:get("hook_server_port")
  assert(type(hook_port) == "number", "hook_port must be a number")
  assert(hook_port <= 65535, "hook_port must be below 65536")

  local hook_secret = ngx.shared.auto_ssl_settings:get("hook_server:secret")
  assert(type(hook_secret) == "string", "hook_server:secret must be a string")

  -- Run dehydrated for this domain, using our custom hooks to handle the
  -- domain validation and the issued certificates.
  --
  -- Disable dehydrated's locking, since we perform our own domain-specific
  -- locking using the storage adapter.
  local result, err = shell_execute({
    "env",
    "HOOK_SECRET=" .. hook_secret,
    "HOOK_SERVER_PORT=" .. hook_port,
    lua_root .. "/bin/resty-auto-ssl/dehydrated",
    "--cron",
    "--accept-terms",
    "--no-lock",
    "--domain", domain,
    "--challenge", "http-01",
    "--config", base_dir .. "/letsencrypt/config",
    "--hook", lua_root .. "/bin/resty-auto-ssl/letsencrypt_hooks",
  })

  -- Cleanup dehydrated files after running to prevent temp files from piling
  -- up. This always runs, regardless of whether or not dehydrated succeeds (in
  -- which case the certs should be installed in storage) or dehydrated fails
  -- (in which case these files aren't of much additional use).
  _M.cleanup(auto_ssl_instance, domain)

  if result["status"] ~= 0 then
    -- React to Let's Encrypt's actual response rather than a configured guess.
    local detail = (result["output"] or "") .. " " .. (err or "")
    if string.find(detail, "rateLimited", 1, true) or string.find(detail, "too many", 1, true) or string.find(detail, "rate limit", 1, true) then
      -- Account-wide limits (e.g. "too many new orders") should pause all
      -- orders; per-registered-domain limits ("...already issued for...") only
      -- affect that domain, so don't back the whole account off for those.
      local account_wide = string.find(detail, "already issued", 1, true) == nil
      if account_wide then
        local backoff = parse_retry_after(detail) or auto_ssl_instance:get("acme_rate_limit_backoff") or 3600
        acme_rate_limit.backoff(backoff)
        ngx.log(ngx.WARN, "auto-ssl: Let's Encrypt rate limit hit; backing off all orders for ", backoff, "s (", domain, ")")
      else
        ngx.log(ngx.NOTICE, "auto-ssl: Let's Encrypt per-domain rate limit for ", domain)
      end
      return nil, "acme rate limit reached"
    end

    ngx.log(ngx.ERR, "auto-ssl: dehydrated failed: ", result["command"], " status: ", result["status"], " out: ", result["output"], " err: ", err)
    return nil, "dehydrated failure"
  end

  ngx.log(ngx.DEBUG, "auto-ssl: dehydrated output: " .. result["output"])

  -- The result of running that command should result in the certs being
  -- populated in our storage (due to the deploy_cert hook triggering).
  local storage = auto_ssl_instance.storage
  local cert, get_cert_err = storage:get_cert(domain)
  if get_cert_err then
    ngx.log(ngx.ERR, "auto-ssl: error fetching certificate from storage for ", domain, ": ", get_cert_err)
  end

  -- Return error if things are still unexpectedly missing.
  if not cert or not cert["fullchain_pem"] or not cert["privkey_pem"] then
    return nil, "dehydrated succeeded, but no certs present"
  end

  return cert
end

function _M.cleanup(auto_ssl_instance, domain)
  assert(string.find(domain, "/") == nil)
  assert(string.find(domain, "%.%.") == nil)

  local dir = auto_ssl_instance:get("dir") .. "/letsencrypt/certs/" .. domain
  local _, rm_err = shell_execute({ "rm", "-rf", dir })
  if rm_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to cleanup certs: ", rm_err)
  end
end

return _M
