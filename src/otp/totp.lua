-- type
export type uri_encoded_string = string | 'None'

-- system
local TOTP = {
	package_metadata = {
		package_name = 'Time-Based One Time Password',
		package_version = 1.0,
		package_creator = 110029109,
	}
}

-- custom dependancy handler
local require = function(dep_name: string)
	local found_dep = script:FindFirstAncestor('SecuritySuite').dependancies:FindFirstChild(dep_name)
	assert(found_dep, string.format('no dependancy of name %s found', dep_name))
	return require(found_dep)
end

-- dependancies
local luaOTP = require('luaOTP').get
local qrcode = require('qrcode')

local luaotp = luaOTP('otp')
local luaOTP_util = luaOTP('util')
local htop = luaOTP('hotp')

-- generate an OTP instance from a secret
function TOTP:get_instance(secret: string)
	return luaotp.new(secret)
end

-- get the code from a OTP instance
function TOTP:get_code(instance): string
	return htop.at(instance, (tick()/30))
end

-- verify a user's code with an OTP instance
function TOTP:verify(user_code: string, instance): boolean
	return htop.verify(user_code, instance, (tick()/30))
end

-- generate a url encoded OTP instance with optional label tag and issuer tag
function TOTP:generate(instance, label: string | 'no label', issuer: string | 'unknown'): uri_encoded_string
	return luaOTP_util.build_uri(instance.secret, label or 'no label', nil, issuer or 'unknown', 'SHA1', 6, 30) or 'None'
end

-- generate an OTP qr-code from a uri encoded OTP instance
function TOTP:generate_qr(code: string)
	return qrcode.creategui(code)
end

return TOTP
