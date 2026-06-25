local _M = {}

-- Acquire one of `max` named slots backed by the `auto_ssl` shared dict, to cap
-- the number of concurrent operations (e.g. dehydrated/ACME invocations, which
-- each shell out via sockproc). Returns the slot index on success, or nil if
-- all `max` slots are currently held.
--
-- Slots are stored with a TTL so they auto-release even if the holder dies
-- (e.g. a worker exits mid-operation), preventing the budget from leaking.
function _M.acquire(prefix, max, ttl)
  if not max or max < 1 then
    return nil
  end

  for i = 1, max do
    local ok = ngx.shared.auto_ssl:add(prefix .. i, true, ttl)
    if ok then
      return i
    end
  end

  return nil
end

function _M.release(prefix, slot)
  if slot then
    ngx.shared.auto_ssl:delete(prefix .. slot)
  end
end

return _M
