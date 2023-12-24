
-- Define the menu entry's callback
local function dialog_menu(fieldinfo)
  local repeater = require("repeater")
  -- 数据包
  local datapacket = fieldinfo.range:bytes():tohex(false, ' ')
  -- 得到所打开的网络接口名称
  local pattern = "on interface%s*(.-)%s*, id"
  local interfaceName = string.match(fieldinfo.display, pattern)
  -- 显示对话框
  local win = TextWindow.new("Repeater");
  win:set_editable(true)
  -- add button to send packet
  win:add_button("Repeat", function()
          local text = win:get_text()
          if text ~= "" then
                  local ret = repeater.RepeatPacket(interfaceName, text)
                  if ret == 0 then
                    print("send successfully")
                  else
                    print("send failed")
                  end 
          end
  end)

  win:set(datapacket)
  
end

-- Notify the user that the menu was created
if gui_enabled() then
  register_packet_menu("Repeat Packet",dialog_menu, "ip")
end

