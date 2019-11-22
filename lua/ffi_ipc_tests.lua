local ffi = require "ffi"

local C       = ffi.C
local ffi_gc  = ffi.gc
local ffi_new = ffi.new
local ffi_str = ffi.string

local at = ngx.timer.at

ffi.cdef[[

typedef struct {
	size_t len;
	unsigned char *data;
} ngx_str_t;

typedef struct ngx_http_lua_ipc_msg_s {
    uint8_t                               refs;
    uint32_t                              size;
    uint32_t                              memsize;
    uint32_t                              idx;
    unsigned char                         type[20];
    unsigned char                        *data;
} ngx_http_lua_ipc_msg_t;

typedef struct ngx_http_lua_ipc_list_node_s {
	struct ngx_http_lua_ipc_list_node_s  *next;
	struct ngx_http_lua_ipc_list_node_s  *prev;
	size_t                                size;
	uint8_t	                              ref_count;
	uint32_t                              idx;
	void                                 *data;
} ngx_http_lua_ipc_list_node_t;

typedef struct ngx_http_lua_ipc_channel_s {
	ngx_str_t                             name;
	void                                 *channel_node;
	unsigned int                          size;
	unsigned int                          refs;
	uint16_t                              flags;
	uint32_t                              counter;
	uint32_t                              subscribers;
	void                                 *zone;
	ngx_http_lua_ipc_list_node_t         *head;
} ngx_http_lua_ipc_channel_t;

typedef struct ngx_http_lua_ipc_subscriber_s {
    uint64_t                              idx;
    ngx_http_lua_ipc_list_node_t         *node;
    ngx_http_lua_ipc_channel_t           *channel;
	uint32_t                              skipped;
    ngx_http_lua_ipc_msg_t               *msg;
} ngx_http_lua_ipc_subscriber_t;

int ngx_http_lua_ffi_ipc_new(const char* shm_name, const char* channel,
	size_t size, uint8_t safe, uint8_t destroy,
	ngx_http_lua_ipc_channel_t **out);

int ngx_http_lua_ffi_ipc_free_channel(ngx_http_lua_ipc_channel_t **channel);

int ngx_http_lua_ffi_ipc_channel_subscribe(ngx_http_lua_ipc_channel_t *channel,
	int start, ngx_http_lua_ipc_subscriber_t **out);

int ngx_http_lua_ffi_ipc_free_subscriber(
	ngx_http_lua_ipc_subscriber_t **subcriber);

int ngx_http_lua_ffi_ipc_add_msg(ngx_http_lua_ipc_channel_t *channel,
	const char *msg, int size);

int ngx_http_lua_ffi_ipc_get_message(ngx_http_lua_ipc_subscriber_t *sub);

void ngx_http_lua_ffi_ipc_ack_msg(ngx_http_lua_ipc_subscriber_t *sub);

]]

local _subscriber = {}

function _subscriber:loop()
	local ok
	local channel = self.channel
	local sub     = self.c_state[0]
	local msg     = sub.msg
	local cb      = self.callback

	while true do
		if self.stopped then
			ngx.log(ngx.NOTICE, "Stopping")
			return
		end

		--if sub.idx <= sub.channel.counter then
			--ngx.log(ngx.NOTICE, "sub idx: ", tonumber(sub.idx), " channel counter: ",
					--tonumber(channel[0].counter))
			local rc = C.ngx_http_lua_ffi_ipc_get_message(sub)
			local str
			if rc == ngx.OK then
				str = ffi_str(sub.msg.data, sub.msg.size)


				ok = cb(str, sub.skipped, self)
				C.ngx_http_lua_ffi_ipc_ack_msg(sub)

				--if ok then
					--C.ngx_http_lua_ffi_ipc_ack_msg(sub)
				--end
			elseif rc == ngx.AGAIN then
				--no new messages
			else
				ngx.log(ngx.NOTICE, "error getting message")
				return
			end
		--end
		ngx.sleep(0.00001)
		--ngx.sleep(0.5)
	end
end

function _subscriber:iter()
	local ok
	local channel = self.channel
	local sub     = self.c_state[0]
	local msg     = sub.msg

	return function()
		while true do
			if self.stopped then
				return false, "stopped"
			end

			local rc = C.ngx_http_lua_ffi_ipc_get_message(sub)

			if rc == ngx.OK then
				local str = ffi_str(sub.msg.data, sub.msg.size)
				C.ngx_http_lua_ffi_ipc_ack_msg(sub)

				return true, str, sub.skipped
			elseif rc == ngx.AGAIN then
				--return true, nil
			else
				return false, "error getting message"
			end

			ngx.sleep(0.0001)
		end
	end
end

function _subscriber:stop()
	self.stopped = true
end

local _M = {}

function _M.add(channel, msg)
	local size = #msg

	local rc = C.ngx_http_lua_ffi_ipc_add_msg(channel[0], msg, size)
	if rc == 0 then
		return true
	else
		return false, "Failed to add msg"
	end
end

function _M:send(msg)
	local size = #msg

	local rc = C.ngx_http_lua_ffi_ipc_add_msg(self.channel[0], msg, size)
	if rc == ngx.OK then
		return true
	elseif rc == ngx.DECLINED then
		return false, "Slow worker in safe mode"
	else
		return false, "Failed to add msg, likely memory error"
	end
end

-- callbacks from C to Lua are slow
-- therefore we use a loop to query the state and retrieve messages when
-- new ones are avilable.
-- TODO should probably implement the alternative callback method, as this
-- can be usefull in some cases.
function _M:subscribe(start)
	if not self.channel then
		return nil, "not initalized"
	end

	start = start or 0

	local c_sub = ffi_gc(ffi_new("ngx_http_lua_ipc_subscriber_t *[1]"),
	                     C.ngx_http_lua_ffi_ipc_free_subscriber)

	if not c_sub then
		return nil, "Failed to create subscriber pointer"
	end

	local rc = C.ngx_http_lua_ffi_ipc_channel_subscribe(self.channel[0], start,
	                                                    c_sub)
	if rc ~= ngx.OK then
		return nil, "Return code: " .. rc
	end

	return setmetatable({
			c_state  = c_sub,
			channel  = self.channel,
			stopped  = false
		}, { __index = _subscriber, })
end

local channels = {}

function _M.new_channel(sh_zone, ch_name, size, safe, destroy)
	local channel = ffi_gc(ffi_new("ngx_http_lua_ipc_channel_t *[1]"),
					       C.ngx_http_lua_ffi_ipc_free_channel)

	if not channel then
		return nil, "Could not create channel pointer"
	end

	local rc = C.ngx_http_lua_ffi_ipc_new(sh_zone, ch_name, size, safe,
	                                      destroy, channel)
	if rc == 0 then
		return setmetatable({
			channel = channel,
		}, { __index = _M })
	elseif rc == -5 then
		return nil, "Not enough memory"
	else
		return nil, "Return code: " .. rc
	end
end

return _M
