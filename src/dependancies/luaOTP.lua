export type digest_type = 'sha1'

-- please point these to proper location
local pseudorandom = Random.new(87265547828262424367)
local basexx = require(script.Parent.basexx)
local sha1 = require(script.Parent.sha1)
local util = {}

util.default_chars = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
	'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
	'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5',
	'6', '7'
}

util.base_uri = "otpauth://%s/%s%s"

util.build_args = function(arr)
	local out = "?"
	for i, v in pairs(arr)do
		out = out .. i .. '=' .. util.encode_url(v) .. '&'
	end
	return string.sub(out, 1, #out-1)
end

util.encode_url = function(url)
	local out = ""
	for i=1, #url do
		local ch = url:sub(i,i)
		local by = string.byte(ch)
		local ch = string.gsub(ch, "^[%c\"<>#%%%s{}|\\%^~%[%]`]+", function(s)
			return string.format("%%%02x", by)
		end)
		if(by > 126)then
			ch = string.format("%%%02x", by)
		end
		out = out .. ch
	end
	return out
end

util.build_uri = function(secret, name, initial_count, issuer_name, algorithm, digits, period)
	local label = util.encode_url(name)
	label = issuer_name and (util.encode_url(issuer_name) .. ':' .. label) or ""

	algorithm = algorithm and string.upper(algorithm) or ""

	local url_args = {
		secret = tostring(secret),
		issuer = issuer_name,
		counter = tostring(initial_count),
		algorithm = algorithm,
		digits = tostring(digits)
	}
	if(initial_count == nil) then
		url_args.period = tostring(period)
	end
	return string.format(util.base_uri, initial_count ~= nil and "hotp" or "totp", label, util.build_args(url_args))
end

util.arr_reverse = function(tab)
	local out = {}
	for i=1, #tab do
		out[i] = tab[1+#tab - i]
	end
	return out
end

util.byte_arr_tostring = function(arr)
	local out = ""
	for i=1, #arr do
		out = out .. string.char(arr[i])
	end
	return out
end

util.str_to_byte = function(str)
	local out = {}
	for i=1, #str do
		out[i] = string.byte(str:sub(i,i))
	end
	return out
end

util.random_base32 = function(length, chars)
	length = length or 16
	chars = chars or util.default_chars
	local out = ""
	for i=1, length do
		out = out .. chars[math.random(1, #chars)]
	end
	return out
end

-- local bit32 = require("bit32")
-- built-in roblox library

local totp = {}
local hotp = {}
local otp = {
	util = util
}

-- otp

--[[
	{...} contains:
		otp.type == totp
			> Number interval
			
		otp.type == hotp
			> nil
			
		otp.type == otp
			> nil
--]]
otp.new = function(secret: string, counter: number, digits: number, digest: digest_type, totp_interval: number)
	local this = {}
	this.secret = secret
	this.digits = digits or 6
	this.digest = digest or "sha1"
	if (totp_interval ~= nil) then -- totp auth
		this.interval = tonumber(totp_interval) or 30
	elseif (counter ~= nil) then -- hotp auth
		this.counter = tonumber(counter) or pseudorandom:NextNumber()
	end

	return this
end

otp.generate_otp = function(instance, input)
	if (input < 0) then
		return nil
	end

	local hash = sha1.hmac_binary(otp.byte_secret(instance), otp.int_to_bytestring(input))
	local offset = bit32.band(string.byte(hash:sub(-1, -1)), 0xF) + 1

	local bhash = util.str_to_byte(hash)

	local code = bit32.bor(
		bit32.lshift(bit32.band(bhash[offset], 0x7F), 24),
		bit32.lshift(bit32.band(bhash[offset + 1], 0xFF), 16),
		bit32.lshift(bit32.band(bhash[offset + 2], 0xFF), 8),
		bit32.lshift(bit32.band(bhash[offset + 3], 0xFF), 0)
	)

	local str_code = tostring(math.floor(code % (10 ^ instance.digits)))
	while #str_code < instance.digits do
		str_code = '0' .. str_code
	end

	return str_code
end

otp.byte_secret = function(instance)
	local missing_padding = #(instance.secret) % 8
	if (missing_padding ~= 0) then
		instance.secret = instance.secret .. string.rep('=', (8 - missing_padding))
	end
	return basexx.from_base32(instance.secret)
end

otp.int_to_bytestring = function(i, padding)
	local bytes = {}
	while (i ~= 0) do
		table.insert(bytes, bit32.band(i, 0xFF))
		i = bit32.rshift(i, 8)
	end
	return string.rep('\0', math.max(0, (padding or 8) - #bytes)) .. util.byte_arr_tostring(util.arr_reverse(bytes))
end

-- hotp
hotp.at = function(instance, counter)
	if (counter == nil and instance.counter ~= nil) then
		counter = instance.counter
	end
	return otp.generate_otp(instance, counter)
end

hotp.verify = function(userkey, instance, counter)
	return tostring(userkey) == tostring(hotp.at(instance, counter))
end

-- totp
totp.at = function(instance, for_time, counter_offset)
	return otp.generate_otp(instance, totp.timecode(instance, tonumber(for_time)) + (counter_offset or 0))
end

totp.now = function(instance, override)
	return otp.generate_otp(instance, totp.timecode(instance, override or os.time()))
end

totp.verify = function(instance, key, for_time, valid_window)
	valid_window = valid_window or 0
	for_time = for_time or os.time()

	if (valid_window > 0) then
		for i=-valid_window, valid_window, 1 do
			if (tostring(key) == tostring(totp.at(instance, for_time, i))) then
				return true
			end
		end
		return false
	end
	return tostring(key) == tostring(totp.at(instance, for_time))
end

totp.timecode = function(instance, for_time)
	return math.floor(for_time/instance.interval)
end

function totp:valid_until(instance, for_time, valid_window)
	valid_window = valid_window or 0
	return for_time + ((self.interval + 1) * valid_window)
end

return {get = function(oauthtype)
	if oauthtype == 'otp' then
		return otp
	elseif oauthtype == 'totp' then
		return totp
	elseif oauthtype == 'util' then
		return util
	else
		return hotp
	end
end}
