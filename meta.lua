---@meta

---@class DNS.Message : NetMessage
---@field header DNS.Message.Header
---@field body DNS.Message.Body

---@class DNS.Message.Header : NetMessage.Header
---@field code string

---@class DNS.Message.Body
---@field record DNS.DNSRecord