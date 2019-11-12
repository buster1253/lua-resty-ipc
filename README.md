# lua-resty-ipc

A WIP ipc implementation.

## Synopsis

Define the shared memory for the IPC to use:

```nginx
http {
	lua_ipc ipc_name size;
}
```

```lua
local ipc = require "ffi_ipc"
local channel, err = ipc.new_channel(ipc_name, channel_name, size, safe, destroy)
if not channel then ... end

local function cb(msg)
    ngx.log(ngx.NOTICE, "msg")
end

local sub, err = channel:subscribe(start, cb)
if not sub then ... end

local ok, err = channel:send("IPC message")
if not ok then ... end
```

### ipc.new_channel

**syntax:** channel, err = ipc.new_channel(ipc_name, channel_name, size, safe,
destroy)

**Context:** ?

The `ipc_name` must match one of the `lua_ipc` definitions. `channel_name` is
the internal name, it can be whatever. `size` defines how many messages
the channel can hold. When `safe` is true the channel will not overwrite
messages when there are still workers waiting to read. When `destroy` is true
the channel will be free'd once all references are gone, this includes
references from lua and subscribers. Subscribers will have their reference
removed when they fall out of the lua scope.

**TODO:** Safe should have a timeout, when the timeout is reached even
unread messages should be removed to prevent a deadlock where a worker is
to slow or broke for some reason.
