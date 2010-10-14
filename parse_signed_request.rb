# Parses Facebooks Signed Request Parameter and returns JSON
# Some borrowing from http://github.com/appoxy/mini_fb/blob/master/lib/mini_fb.rb && http://sunilarora.org/parsing-signedrequest-parameter-in-python-bas

require "openssl"
require "base64"
require "cgi"
require "yajl"

def base64_url_decode(st)
  st = st + "=" * (4 - st.size % 4) unless st.size % 4 == 0
  return Base64.decode64(st.tr("-_", "+/"))
end

def verify_signed_request(secret, sign, payload)
  sig = base64_url_decode(sign)
  expected_sig = OpenSSL::HMAC.digest('SHA256', secret, payload.tr("-_", "+/"))
  return sig == expected_sig
end

def parse_signed_request
  secret = "SECRET"
  signed_request = "SIGNED_REQUEST_STRING"
  sign, payload = signed_request.split(".")

  data = Yajl::Parser.parse(base64_url_decode(payload))
  if verify_signed_request(secret, sign, payload)
    return "verified"
  else
    return "not verified"
  end
end

parse_signed_request




