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
    -- TODO: Detect the format and print it appropriately
    io.write(header)
--    if(options.binary) then
      io.write("\n")
      nsedebug.print_hex(value)
--    elseif(options.hex) then
--      io.write(string.format("%x", value) .. "\n")
--    elseif(options.format_string) then
--      io.write(string.format(format_string, value) .. "\n")
--    else
--      io.write(tostring(value) .. "\n")
--    end
  end,

  call = function(self, name, func, args, expected_values, options)
    local results
    options = options or {}

    -- Call the function with the given arguments
    results = {func(table.unpack(args))}

    -- Verify the function's results
    self:check(name, results, expected_values, options)

    -- Return the results so the program testing can use them
    return table.unpack(results)
  end,

  ---Check whether the list of values and expected_values matches; if they
  -- don't, print an error to the screen and log it as a failure.
  --
  -- @param name The name of the function, which will be displayed to the
  --        screen for the user.
  -- @param values A single value or an array of values that represent the
  --        values that some function returned and that need to be validated.
  -- @param expected_alues A single value or an array of values that represent
  --        the expected output of the function. These will be matched to the
  --        values array, and should therefore be the same size.
  check = function(self, name, values, expected_values, options)
    local i, value, expected
    options = options or {}

    -- Make sure values and expected_values are tables
    if(type(values) ~= 'table') then
      values = {values}
    end
    if(type(expected_values) ~= 'table') then
      expected_values = {expected_values}
    end

    -- Keep track of the total number of checks
    self.total = self.total + 1

    -- Make sure we have the same amount of values and expected_values
    if(#values ~= #expected_values) then
      self.fail = self.fail + 1

      io.write("FAIL: " .. name .. ":\n")
      io.write(string.format("Expected: %d values\n", #expected_values))
      io.write(string.format("Found:    %d values\n", #values))

      return
    end

    -- Loop through the values and make sure each pair of values and expected_values matches
    for i = 1, #values do
      value = values[i]
      expected = expected_values[i]

      -- If it doesn't match, log a fail and return
      if(value ~= expected) then
        self.fail = self.fail + 1

        io.write("FAIL (return #" .. i .. "): " .. name .. ":\n")
        self:display("Expected: ", expected, options)
        self:display("Found:    \n", value, options)
        return false
      end
    end

    -- If we successfully finished the loop, then life's good
    self.success = self.success + 1
    io.write("PASS: " .. name)
    if(options.display_pass) then
      self:display("Data:     ", expected, options)
    else
      io.write("\n")
    end
  end,

  ---Prints a report of how many functions failed / succeeded.
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
