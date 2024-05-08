local _M = {}
csr = require("resty.openssl.x509.csr")
x509 = require("resty.openssl.x509")
pkey = require("resty.openssl.pkey")
bn = require("resty.openssl.bn")
x509_name = require("resty.openssl.x509.name")
rand = require "resty.openssl.rand"
x509_extension = require "resty.openssl.x509.extension"
alt = require("resty.openssl.x509.altname").new()

--  TODO
function _M.readCA()
    local pkFile, err, code = assert(io.open("/var/cert/ca.key"))
    if not pkFile then
       print("Error opening ca.key", err)
       -- Do something to handle the error
    end

    local csrFile, err, code = assert(io.open("/var/cert/ca.crt"))
    if not csrFile then
       print("Error opening ca.crt", err)
       -- Do something to handle the error
    end

    local key = pkFile:read("*all")
    local cert = csrFile:read("*all")
    csrFile:close()
    pkFile:close()
    return key, cert
end

function _M.generate_crs(domain)
    local domain_pkey, err = pkey.new({
      type = 'EC',
      curve = 'prime256v1',
    })
    if err then
      error(err)
    end

    -- TOOD: Get real info
    local name = assert(x509_name.new()
    :add("C", "PE")
    :add("ST", "Lima")
    :add("L", "Lima")
    :add("O", "IT")
    :add("OU", "IT Department")
    :add("CN", domain))

    local _
    _, err = csr:set_subject_name(name)
    if err then
        return nil, err
    end

    _, err = csr:set_pubkey(domain_pkey)
     if err then
       return nil, err
     end

     _, err = csr:sign(domain_pkey)
     if err then
       return nil, err
     end

     return csr, domain_pkey
end

function _M.generate_ssl(domain)

    key, cacrt = _M.readCA()

    local cakey, err = pkey.new(key, {
        format = "PEM",
        type = "pr",
        passphrase = "test",
    })
    if not cakey then
        ngx.log(ngx.ERR, "failed to parse ca key ", " on ", err)
    end

    local cacert, err = x509.new(cacrt, "*")
    if not cacert then
        ngx.log(ngx.ERR, "failed to parse ca cert ", " on ", err)
    end
    local wildcard = "*." .. domain
    local pubkey = pkey.new { bits = 2048 }
    alternative = alt.new()
    alternative:add("DNS", domain)
    alternative:add("DNS", domain)
    local crt = x509.new()
    assert(crt:set_pubkey(pubkey))
    assert(crt:set_version(3))
    assert(crt:set_serial_number(bn.from_binary(rand.bytes(16))))

    -- Valid 3 month
    local now = os.time()
    assert(crt:set_not_before(now))
    assert(crt:set_not_after(now + 86400 * 3 * 30))

    -- TOOD: Get real info
    local name = assert(x509_name.new()
    :add("C", "PE")
    :add("ST", "Lima")
    :add("L", "Lima")
    :add("O", "La Republica")
    :add("OU", "IT Department")
    :add("CN", wildcard))

    assert(crt:set_subject_name(name))
    assert(crt:set_subject_alt_name(alternative))
    assert(crt:set_issuer_name(cacert:get_subject_name()))

    -- Not a CA
    assert(crt:set_basic_constraints { CA = false })
    assert(crt:set_basic_constraints_critical(true))

    -- Only allowed to be used for TLS connections (client or server)
    assert(crt:add_extension(x509_extension.new("extendedKeyUsage", "serverAuth,clientAuth")))

    -- RFC-3280 4.2.1.2
    assert(crt:add_extension(x509_extension.new("subjectKeyIdentifier", "hash", { subject = crt})))

    assert(crt:sign(cakey))
    local pem = crt:tostring("PEM")
    local privateKey = pubkey:tostring("private")
    local cacertPEM = cacert:tostring("PEM")
    return pem, privateKey, cacertPEM
end

-- TODO: Implement cache
function _M.get_ssl(domain)
    local json = require("json")
    local memcached = require "resty.memcached"
    local memc, err = memcached:new()
    if not memc then
        ngx.log(ngx.ERR, "failed to instantiate memc: ", err)
        return
    end

    memc:set_timeout(1000) -- 1 sec

    local ok, err = memc:connect("memcached", 11211)
    if not ok then
        ngx.log(ngx.ERR, "failed to connect to memcache: ", err)
        return
    end

    local res, flags, err = memc:get(domain)

    if not res or err then
        ngx.log(ngx.DEBUG, "No SSL for domain: ", domain, err)
        pem, privateKey, cacertPEM = _M.generate_ssl(domain)
        bundle = pem .. cacertPEM
        local encoded = json.encode({
          pem = pem,
          privateKey = privateKey,
          bundle = bundle
        })
        local ok, err = memc:set(domain, encoded)
        if not ok then
            ngx.log(ngx.ERR, "failed to set ssl for: ", domain, err)
            return
        end
        return pem, privateKey, bundle
    end
    local decoded = json.decode(res)
    return decoded.pem, decoded .privateKey, decoded.bundle
end

return _M