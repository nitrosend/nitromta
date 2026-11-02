-- KumoMTA as the harness runs it: authenticated submission over STARTTLS,
-- and authenticated HTTP injection over HTTPS for the API-ingress comparison;
-- signing with the harness's RSA-2048 key (rsa-sha256, relaxed/relaxed, the
-- same headers as every system); and delivery over required STARTTLS to the
-- sink by its MX. With FORCE_SYNC=1 every message is saved with a synced write
-- before the 250 reply; with FORCE_SYNC=0, as
-- KumoMTA ships, the write is not synced.
local kumo = require 'kumo'

local FORCE_SYNC = os.getenv 'FORCE_SYNC' == '1'
local PASSWORD = os.getenv 'BENCH_PASSWORD'
-- Every system retries on the same schedule and keeps to the same connections
-- per receiver site; the harness passes both from the profile.
local CONNECTIONS = assert(tonumber(os.getenv 'BENCH_CONNECTIONS'), 'BENCH_CONNECTIONS')
local RETRY_FIRST = assert(os.getenv 'BENCH_RETRY_FIRST_SECONDS') .. ' seconds'
local RETRY_MAX = assert(os.getenv 'BENCH_RETRY_MAX_SECONDS') .. ' seconds'
-- Where a profile needs a throttling response, KumoMTA answers throttling as
-- its deployments do: its shaping helper reports deliveries to
-- the traffic-shaping automation daemon, which suspends a site whose replies
-- match a rule. The rules are the harness's own (start writes them), not the
-- shipped defaults, which limit every site far below what every system here
-- may open.
local TSA = os.getenv 'BENCH_TSA' == 'true'
local shaper
if TSA then
  shaper = require('policy-extras.shaping'):setup_with_automation {
    publish = { 'http://127.0.0.1:8008' },
    subscribe = { 'http://127.0.0.1:8008' },
    no_default_files = true,
    extra_files = { '/run/kumomta/shaping.toml' },
  }
end
-- An ablation may leave out signing, or TLS on delivery.
local SIGN = assert(os.getenv 'BENCH_SIGN') == 'true'
local DELIVERY_TLS = assert(os.getenv 'BENCH_DELIVERY_TLS') == 'true'
local SPOOL = '/var/spool/kumomta'

-- KumoMTA writes its spool on the SMTP server's threads, so a synced write
-- holds a thread for the whole flush, and RocksDB can group only as many
-- synced writes as there are threads waiting. On the quick profile's 4 CPUs,
-- durable runs sustained 750 messages a second with the default thread
-- count, and 2,000, 2,500, 1,500 and 2,000 with 8, 16, 32 and 64 threads
-- (27 October 2026). The full profile tunes it again.
--
-- HTTP injection saves each message on its own runtime's threads, 3/8 of the
-- CPUs by default (one, here), so it is given the same 16 as SMTP. It has not
-- been tuned separately yet.
kumo.on('pre_init', function()
  kumo.set_smtpsrv_threads(16)
  kumo.set_httpinject_threads(16)
end)

kumo.on('init', function()
  kumo.define_spool {
    name = 'data',
    path = SPOOL .. '/data',
    kind = 'RocksDB',
  }
  kumo.define_spool {
    name = 'meta',
    path = SPOOL .. '/meta',
    kind = 'RocksDB',
  }
  -- Logs go to the measured volume, as Postfix's do.
  kumo.configure_local_logs {
    log_dir = SPOOL .. '/logs',
  }
  if shaper then
    shaper.setup_publish()
  end
  kumo.start_esmtp_listener {
    listen = '0.0.0.0:587',
    hostname = 'sut.bench.test',
    tls_certificate = '/etc/bench/tls/sut.crt',
    tls_private_key = '/etc/bench/tls/sut.key',
    -- One generator connection carries every message of a step.
    max_messages_per_connection = 1000000000,
  }
  -- The load generator is not a trusted host, so every request is
  -- authenticated.
  kumo.start_http_listener {
    listen = '0.0.0.0:8443',
    use_tls = true,
    tls_certificate = '/etc/bench/tls/sut.crt',
    tls_private_key = '/etc/bench/tls/sut.key',
  }
end)

kumo.on('http_server_validate_auth_basic', function(user, password)
  return user == 'bench' and password == PASSWORD
end)

kumo.on('smtp_server_auth_plain', function(authz, authc, password, conn_meta)
  return authc == 'bench' and password == PASSWORD
end)

-- An authenticated session may relay from the sending domain: KumoMTA's
-- counterpart of Postfix's permit_sasl_authenticated.
kumo.on('get_listener_domain', function(domain, listener, conn_meta)
  if domain == 'bench.test' and conn_meta:get_meta 'authz_id' == 'bench' then
    local peer = conn_meta:get_meta 'received_from'
    return kumo.make_listener_domain {
      relay_from = { peer:match '^(.+):%d+$' },
    }
  end
end)

-- Every message, however it arrived, is saved as FORCE_SYNC says and signed
-- before it is spooled.
local function prepare(msg)
  msg:set_force_sync(FORCE_SYNC)
  if not SIGN then
    return
  end
  msg:dkim_sign(kumo.dkim.rsa_sha256_signer {
    domain = 'bench.test',
    selector = 'bench',
    headers = { 'From', 'To', 'Subject', 'Date', 'Message-ID' },
    key = '/etc/bench/dkim/private.pem',
    header_canonicalization = 'Relaxed',
    body_canonicalization = 'Relaxed',
  })
end

kumo.on('smtp_server_message_received', prepare)
kumo.on('http_message_generated', prepare)

kumo.on('get_queue_config', function(domain, tenant, campaign, routing_domain)
  return kumo.make_queue_config {
    retry_interval = RETRY_FIRST,
    max_retry_interval = RETRY_MAX,
  }
end)

-- A ready queue large enough that no message is put back for want of room.
-- With automation, the same settings come from the harness's shaping rules.
kumo.on('get_egress_path_config', function(domain, egress_source, site_name)
  if shaper then
    return shaper.get_egress_path_config(domain, egress_source, site_name)
  end
  return kumo.make_egress_path {
    enable_tls = DELIVERY_TLS and 'RequiredInsecure' or 'Disabled',
    connection_limit = CONNECTIONS,
    max_ready = 100000,
  }
end)
