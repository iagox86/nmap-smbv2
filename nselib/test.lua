---
-- TODO
--
--

local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local nsedebug = require "nsedebug"

_ENV = stdnse.module("test", stdnse.seeall)

Test =
{
  new = function(self)
    local o = { }
    setmetatable(o, self)
    self.__index = self

    o.success = 0
    o.fail = 0
    o.total = 0

    return o
  end,

  display = function(self, header, value, options)
    io.write(header)
    if(options.binary) then
      io.write("\n")
      nsedebug.print_hex(value)
    elseif(options.hex) then
      io.write(string.format("%x", value) .. "\n")
    elseif(options.format_string) then
      io.write(string.format(format_string, value) .. "\n")
    else
      io.write(value .. "\n")
    end
  end,

  call = function(self, name, value, expected, options)
    options = options or {}

    self.total = self.total + 1

    if(value ~= expected) then
      self.fail = self.fail + 1

      io.write("FAIL: " .. name .. ":\n")
      self:display("Expected: ", expected, options)
      self:display("Found:    ", value, options)
    else
      self.success = self.success + 1
      io.write("PASS: " .. name)
      if(options.display_pass) then
        self:display("Data:     ", expected, options)
      else
        io.write("\n")
      end
    end
  end,

  report = function(self)
    print(("-"):rep(80))
    print(string.format("SUCCESS  : %d", self.success))
    print(string.format("FAIL     : %d", self.fail))
    print("--------")
    print(string.format("RESULT   : %d / %d => %.2f%%", self.success, self.total, 100 * self.success / self.total))
    print(("-"):rep(80))
  end
}

return _ENV;
