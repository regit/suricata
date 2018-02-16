.. _lua-output:

Lua Output
==========

Lua scripts can be used to generate output from Suricata.

Script structure
----------------

A script defines 4 functions: init, setup, log, deinit

* init -- registers where the script hooks into the output engine
* setup -- does per output thread setup
* log -- logging function
* deinit -- clean up function

Example:

::

  function init (args)
      local needs = {}
      needs["protocol"] = "http"
      return needs
  end

  function setup (args)
      filename = SCLogPath() .. "/" .. name
      file = assert(io.open(filename, "a"))
      SCLogInfo("HTTP Log Filename " .. filename)
      http = 0
  end

  function log(args)
      http_uri = HttpGetRequestUriRaw()
      if http_uri == nil then
          http_uri = "<unknown>"
      end
      http_uri = string.gsub(http_uri, "%c", ".")

      http_host = HttpGetRequestHost()
      if http_host == nil then
          http_host = "<hostname unknown>"
      end
      http_host = string.gsub(http_host, "%c", ".")

      http_ua = HttpGetRequestHeader("User-Agent")
      if http_ua == nil then
          http_ua = "<useragent unknown>"
      end
      http_ua = string.gsub(http_ua, "%g", ".")

      ts = SCPacketTimeString()
      ipver, srcip, dstip, proto, sp, dp = SCFlowTuple()

      file:write (ts .. " " .. http_host .. " [**] " .. http_uri .. " [**] " ..
             http_ua .. " [**] " .. srcip .. ":" .. sp .. " -> " ..
             dstip .. ":" .. dp .. "\n")
      file:flush()

      http = http + 1
  end

  function deinit (args)
      SCLogInfo ("HTTP transactions logged: " .. http);
      file:close(file)
  end

YAML
----

To enable the lua output, add the 'lua' output and add one or more
scripts like so:

::

  outputs:
    - lua:
        enabled: yes
        scripts-dir: /etc/suricata/lua-output/
        scripts:
          - tcp-data.lua
          - flow.lua

The scripts-dir option is optional. It makes Suricata load the scripts
from this directory. Otherwise scripts will be loaded from the current
workdir.

Developping lua output script
-----------------------------

You can use functions described in :ref:`Lua Functions <lua-functions>`
