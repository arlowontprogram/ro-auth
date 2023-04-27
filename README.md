# ro-auth
ro-auth is a luau friendly approach to authentication using methods like TOTP

ro-auth is (no longer) in development. *any* and *every* bug report is welcome to be reported.

***you are the sole point of security. ro-auth is only as secure as way you save these keys***

## ***oauth***
### ***TOTP***

TOTP provides several different functions.
as of TOTP v1.0 the functions are as listed:

new_instance:
```lua
-- creates a new OTP instance with the following *secret* key
-- this is the bear-bones of TOTP.
TOTP:new_instance(secret: string): <OTP-instance>
```

get_code:
```lua
-- returns the current TOTP code from a OTP instance
TOTP:get_code(instance: <OTP-instance>): <string>
```

verify:
```lua
-- returns a boolean dictating if a user code is the same as the server's code
TOTP:verify(user_code: string, instance: <OTP-instance>): <boolean>
```
generate_uri:
```lua
-- generates a uri safe TOTP code with optional label and issuer tags
TOTP:generate_uri(instance: <OTP-instance>, label: string | 'no label', issuer: string | 'unknown'): <string>
```
generate_qr:
```lua
-- generates a ROBLOX-ONLY screengui-based qr-code from a uri encoded TOTP instance
TOTP:generate_qr(instance: <OTP-instance>): <screengui | userdata>
```

## ***license***
ro-auth comes under an MIT license, **although**

required dependancies come under several different licences listed under the ``src/external-licenses.lua`` file.
