local ntlm = require('ntlm')
local nsedebug = require('nsedebug')

description = [[
Retrieves the day and time from the Daytime service.
]]

author = "Diman Todorov"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

hostrule = function()
  return true
end

action = function(host, port)
  test = ntlm.Ntlm:new('Domain\\User', 'Password')
  test.test()
end



