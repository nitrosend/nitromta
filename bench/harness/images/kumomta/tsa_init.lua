-- KumoMTA's traffic-shaping automation daemon, for the throttled profile: it
-- reads the harness's shaping rules, which start writes, and nothing else.
local tsa = require 'tsa'
local kumo = require 'kumo'

kumo.on('tsa_init', function()
  tsa.start_http_listener {
    listen = '127.0.0.1:8008',
    trusted_hosts = { '127.0.0.1' },
  }
end)

kumo.on('tsa_load_shaping_data', function()
  return kumo.shaping.load { '/run/kumomta/shaping.toml' }
end)
