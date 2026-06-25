local _M = {}

-- Account-wide fixed-window rate limiter for Let's Encrypt orders.
--
-- Both new issuance and renewal create ACME orders against the same Let's
-- Encrypt account and therefore share the same rate limits (notably 300 new
-- orders per 3 hours). This must be enforced globally across both paths, so a
-- single shared counter in the `auto_ssl` shared dict is used.
--
-- Returns true if an order is allowed, false if it should be skipped. Combines
-- two mechanisms:
--   1. Reactive backoff: if Let's Encrypt actually rate-limited us recently (as
--      detected from a real ACME response, see acme_rate_limit.backoff), stay
--      backed off until that cooldown clears. This adapts automatically to the
--      account's real limits, including after a limit increase -- we only back
--      off when LE itself says so, with no configured number to maintain.
--   2. Proactive cap (optional): with max set, limit orders to `max` per
--      `period` so we avoid hitting LE's wall in the first place.
function _M.allow(max, period)
  local backoff_until = ngx.shared.auto_ssl:get("acme_rate_limited_until")
  if backoff_until and backoff_until > ngx.now() then
    return false
  end

  if not max or max < 1 then
    return true
  end

  -- incr with init=0 and init_ttl=period creates the counter on the first
  -- order of a window with a TTL of `period`, so the window resets `period`
  -- seconds later. Subsequent orders within the window just increment.
  local dict = ngx.shared.auto_ssl
  local count, err = dict:incr("acme_order_count", 1, 0, period)
  if not count then
    ngx.log(ngx.ERR, "auto-ssl: failed to track ACME order rate: ", err)
    -- Fail open rather than block all issuance/renewal on a tracking error.
    return true
  end

  return count <= max
end

-- Record an account-wide rate-limit response from Let's Encrypt and back off all
-- issuance and renewal for `seconds`. Called from the ACME provider when an
-- order is rejected with an account-wide rate-limit error, so the actual LE
-- response (not a configured guess) drives how long we pause.
function _M.backoff(seconds)
  ngx.shared.auto_ssl:set("acme_rate_limited_until", ngx.now() + seconds, seconds)
end

return _M
