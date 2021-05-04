local kong = kong
local ngx = ngx
--local concat = table.concat
--local lower = string.lower
--local find = string.find
local MyHeader = {}
--local cjson = require "cjson.safe" 
local cjson = require "cjson"

local table_insert = table.insert
local get_uri_args = kong.request.get_query
local set_uri_args = kong.service.request.set_query
local clear_header = kong.service.request.clear_header
local get_header = kong.request.get_header
local set_header = kong.service.request.set_header
local get_headers = kong.request.get_headers
local set_headers = kong.service.request.set_headers
local set_method = kong.service.request.set_method
local set_path = kong.service.request.set_path
local get_raw_body = kong.request.get_raw_body
local set_raw_body = kong.service.request.set_raw_body
local encode_args = ngx.encode_args
local ngx_decode_args = ngx.decode_args
local type = type
local str_find = string.find
local pcall = pcall
local pairs = pairs
local error = error
local rawset = rawset
--local pl_copy_table = pl_tablex.deepcopy

--local jwt = require "luajwt"
local key = "odin"
local alg = "HS256"
local username = ""

local jwt_decoder = require "kong.plugins.myheader.jwt_parser"

local uuid = require "kong.tools.utils".uuid
local worker_uuid
local worker_counter
local generators

local fmt = string.format
local kong = kong
local type = type
local error = error
local ipairs = ipairs
local tostring = tostring
local re_gmatch = ngx.re.gmatch

local pl_template = require "pl.template"

MyHeader.PRIORITY = 1000

do
  local worker_pid = ngx.worker.pid()
  local now = ngx.now
  local var = ngx.var
  local fmt = string.format

  generators = {
    ["uuid"] = function()
      return uuid()
    end,
    ["uuid#counter"] = function()
      worker_counter = worker_counter + 1
      return worker_uuid .. "#" .. worker_counter
    end,
    ["tracker"] = function()
      return fmt("%s-%s-%d-%s-%s-%0.3f",
        var.server_addr,
        var.server_port,
        worker_pid,
        var.connection, -- connection serial number
        var.connection_requests, -- current number of requests made through a connection
        now() -- the current time stamp from the nginx cached time.
      )
    end,
  }
end


-- String to array decoder
local function read_json_body(body)
  if body then
    return cjson.decode(body)
  end
end

local function parse_json(body)
  if body then
    local status, res = pcall(cjson.decode, body)
    if status then
      return res
    end
  end
end


local function param_value(source_template, config_array)
  if not source_template or source_template == "" then
    return nil
  end

  -- find compiled templates for this plugin-configuration array
  local compiled_templates = template_cache[config_array]
  if not compiled_templates then
    compiled_templates = {}
    -- store it by `config_array` which is part of the plugin `conf` table
    -- it will be GC'ed at the same time as `conf` and hence invalidate the
    -- compiled templates here as well as the cache-table has weak-keys
    template_cache[config_array] = compiled_templates
  end

  -- Find or compile the specific template
  local compiled_template = compiled_templates[source_template]
  if not compiled_template then
    compiled_template = pl_template.compile(source_template, compile_opts)
    compiled_templates[source_template] = compiled_template
  end

  return compiled_template:render(template_environment)
end

local function iter(config_array)
  print("start iter function ")
  return function(config_array, i, previous_name, previous_value)
    i = i + 1
	 print(i)
    local current_pair = config_array[i]
	 print((current_pair))
    if current_pair == nil then -- n + 1
      return nil
    end
print("first if ended")
    local current_name, current_value = current_pair:match("^([^:]+):*(.-)$")
	print(current_name)
    if current_value == "" then
      return i, current_name
    end

    local res, err = param_value(current_value, config_array)
    if err then
      return error("[request-transformer] failed to render the template " ..
                   current_value .. ", error:" .. err)
    end

    kong.log.debug("[request-transformer] template `", current_value,
                   "` rendered to `", res, "`")

    return i, current_name, res
  end, config_array, 0
end

local function check_body_parameters(conf, parameters, content_length)
  print("start check_body_parameters function ")
  local checked = false
  --local content_length = (body and #body) or 0
  --local parameters = parse_json(body)
  if parameters == nil then
    if content_length > 0 then
      return false
    end
    --parameters = {}
  end

  --if conf.check.body > 0 then
  print(type(conf.check.body))
  --print(conf.check.body)
    for _, name, value in iter(conf.check.body) do
	print(name)
      if not parameters[name] then
	    print("body param not found " );
		return false
		
      end
    end
  --end
   print("end check_body_parameters function ")
   return true

end

 local function update_body_params(conf,token)
	
	  local jwt ,err2= jwt_decoder:new(token)
	  local claims = jwt.claims
	  local jwt_username = claims["username"]
	if jwt_username then
	  print("start Body modification function ")
		local body = get_raw_body()
		local parameters = parse_json(body)
		local content_length = (body and #body) or 0
		local body_check = check_body_parameters(conf , parameters , content_length)
		print(body_check)
		if body_check == true then
			print("Parameter Listed are present in request body")
		else
			return false, { status = 401, message = "Parameter Listed are not present in request body" }
			--return kong.response.exit(401,{ message = "Parameter Listed are not present in request body" })
		end
		
		
		if parameters == nil then
			parameters = {}			
		end
		print(parameters["email"])
		print(parameters["TenantId"])
		
		if not parameters["TenantId"] or not parameters["OMSId"] then
			return false, { status = 401, message = "Invalid body params : TenantId/OMSId" }
		end
		parameters["LastUpdateTime"] = os.time(os.date("!*t"))
		parameters["UpdatedBy"] = jwt_username
		print(conf.generator)
		local correlation_id = generators[conf.generator]()
		parameters["TraceId"] = correlation_id
		print(correlation_id)
		local bodyNew = cjson.encode(parameters)
		set_raw_body(bodyNew)
		print("End Body modification function ")
		return true
	else
		return false, { status = 401, message = "No username found JWT token" }
	end
	
end

local function verify_jwt_signature(token)
--verify token type
local token_type = type(token)
  if token_type ~= "string" then
    if token_type == "nil" then
      return false, { status = 401, message = "Unauthorized" }
    elseif token_type == "table" then
      return false, { status = 401, message = "Multiple tokens provided" }
    else
      return false, { status = 401, message = "Unrecognizable token" }
    end
  end
  
  -- Decode token to find out who the consumer is
  local jwt, err = jwt_decoder:new(token)
  if err then
    return false, { status = 401, message = "Bad token; " .. tostring(err) }
  end  
  
  if not jwt:verify_signature(key) then
    return false, { status = 401, message = "Invalid signature" }
  end
  return true
  
end


local function verify_and_transform_json_body(conf)
	print("start verify_and_transform_json_body function ")
	local token = ""
	print(kong.request.get_method())
	local request_headers = kong.request.get_headers()
	local token_header = request_headers[conf.header_value] 
	if token_header then
      local iterator, iter_err = re_gmatch(token_header, "\\s*[Bb]earer\\s+(.+)")
      local m, err = iterator()
	  token = m[1] 
	else
		return kong.response.exit(401,{ message = "Bearer Token not found in header" })
	end
	local ok, err = verify_jwt_signature(token)
	print(ok)
	--print(err.message)
	if not ok then
		print("Inside Not ok")
		return kong.response.exit(err.status, { message = err.message })	
	elseif kong.request.get_method() == "POST" then	
		local body_ok,body_err = update_body_params(conf,token)
		if not body_ok then
			return kong.response.exit(body_err.status, { message = body_err.message })	
		end
	end
	
	print("end verify_and_transform_json_body function ")
end
 
function MyHeader:init_worker()
  worker_uuid = uuid()
  worker_counter = 0
end

function MyHeader:header_filter(conf)
 
end


function MyHeader:body_filter(config)

end

function MyHeader:access(conf)
  print("start access function ")
  verify_and_transform_json_body(conf)
  print("end access function ")
end
return MyHeader

