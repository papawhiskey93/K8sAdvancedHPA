
local strings_array = {
  type = "array",
  default = {},
  required = true,
  elements = { type = "string" },
}

local strings_array_record = {
  type = "record",
  fields = {
    { body = strings_array },
    { headers = strings_array },
  },
}

return {
  name = "myheader",
  fields = {
    { config = {
        type = "record",
        fields = {
          { header_value = { type = "string", default = "Authorization", }, },
	      { generator = { type = "string", default = "uuid#counter", one_of = { "uuid", "uuid#counter", "tracker" }, }, },
	      { check    = strings_array_record  },
        },
    }, },
  }
}

