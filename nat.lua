pos.require("net.rttp")
pos.require('net.rtml')
local rtmlLoader = pos.require('net.rtml.rtmlLoader')

---@class NAT: LANController.Service
---@field config LANControllerConfig
---@field private __handlerId number?
---@field private __extInterface NetInterface
---@field private __extModem ModemPeripheral
---@field private __intInterface NetInterface
---@field private __intModem ModemPeripheral
---@field private __intMessages { string: boolean }
---@field private __extMessages { string: boolean }
---@field private __outMessages { NetAddress: { number: NAT.MessageRecord } }
---@field private __conIdTable { string: number }
---@field private __inMessages { NetAddress: { number: NAT.MessageRecord } }
---@field private __sockets { number: NAT.SocketRecord }
---@field private __socketsByOrigin { NetAddress: { NetAddress: number } }
local NAT = {}

local NAT_MT = {
    __index = NAT
}

local FORWARDING_TABLE = 'forwarding'
-- domain: string?, port: string?, dest: string NOT_NIL

---@class NAT.ForwardingRecord
---@field domain string?
---@field port number?
---@field dest string|number

---@class NAT.MessageRecord
---@field dest NetAddress
---@field destConId number?
---@field msgid number

---@class NAT.SocketRecord
---@field origin NetAddress
---@field dest NetAddress
---@field originSocketId number
---@field conId number

---@param controller LANController
---@param logger Logger
function NAT.new(controller, logger)
    local o = {}
    setmetatable(o, NAT_MT)
    o:__init__(controller, logger)
    return o
end

---@package
---@param controller LANController
---@param logger Logger
function NAT:__init__(controller, logger)
    self.controller = controller
    self.config = controller.config
    self.logger = logger

    self.__intInterface = controller.outsideInterface
    self.__intModem = controller.insideInterface:getModem()
    self.__extInterface = controller.outsideInterface
    self.__extModem = controller.outsideInterface:getModem()

    self.__intMessages = {}
    self.__extMessages = {}
    self.__outMessages = {}
    self.__inMessages = {}
end

---@package
---@param cmd string
---@vararg string|number
function NAT:__dbQuery(cmd, ...)
    return self.controller.dbQuery(self, cmd, ...)
end

local function getMsgIdentifier(msg)
    local id = net.getOriginString(msg)
    return id .. ':' .. msg.msgid
end

function NAT:start()
    self.__handlerId = pos.addEventHandler(function(event)
        local _, side, port, _, msg = unpack(event)
        if side == self.config.modems.inside then
            local msgid = getMsgIdentifier(msg)
            if self.__intMessages[msgid] then
                return
            end
            self.__intMessages[msgid] = true
            self:__messageHandlerInt(port, msg)
        elseif side == self.config.modems.outside then
            local msgid = getMsgIdentifier(msg)
            if self.__extMessages[msgid] then
                return
            end
            self.__extMessages[msgid] = true
            self:__messageHandlerExt(port, msg)
        end
    end, 'modem_message', 'nat')
end

function NAT:__getConIdStr(msg)
    local originStr = net.getOriginString(msg)
    local destStr = msg.dest
    if msg.header.domain then
        destStr = msg.header.domain
    elseif msg.header.destConId then
        destStr = destStr .. ':' .. msg.header.destConId
    end
    
    local paring = originStr .. '-' .. destStr
    local conId = nil
    if self.__conIdTable[paring] then
        conId = self.__conIdTable[paring]
    else
        conId = self.__extInterface:useMsgId()
    end
    return conId
end

---
---@package
---@param port number
---@param msg NetMessage
function NAT:__messageHandlerInt(port, msg)
    local sysTime = os.epoch()

    if type(msg.dest) == 'string' then
        return
    elseif msg.dest < 0x0 or msg.dest >= 0xffffffff then                                                                      -- inside valid ip range [0.0.0.0 - 255.255.255.255)
        return
    elseif msg.dest >= 0xa9fe0000 and msg.dest <= 0xa9feffff then                                                             -- not link local
        return
    elseif msg.dest >= 0xe0000000 and msg.dest <= 0xefffffff then                                                             -- not multicast
        return
    elseif msg.dest >= self.config.baseAddr and msg.dest <= self.config.baseAddr + (0xffffffff - self.config.subnetMask) then -- not our local network
        return
    end

    if msg.header.type == net.sockets.NetSocketType then
        ---@cast msg NetSocket.Message
        local socketID = self.__socketsByOrigin[msg.origin][msg.dest]
        if not socketID then
            socketID = self.__extInterface:useMsgId()
            self.__socketsByOrigin[msg.origin][msg.dest] = socketID
        end
        self.__sockets[socketID] = {
            origin = msg.origin,
            conId = msg.header.conId,
            socketId = msg.header.originSocketId,
            dest = msg.dest,
        }
        msg.header.destSocketId = socketID
    end
    
    if msg.header.conId then
        local outConId = msg.header.conId
        local msgRecord = self.__inMessages[outConId][msg.msgid]
        if msgRecord then
            self.__outMessages[outConId][msg.msgid] = nil

            msg.header.destConId = msgRecord.destConId
            msg.header.conId = nil

            ---@type NetMessage
            local inMsg = {
                origin = self.__extInterface:getIP() --[[@as NetAddress]],
                dest = msg.dest,
                header = msg.header,
                body = msg.body,
                msgid = msgRecord.msgid,
                port = port,
                reply = function () end
            }
            self.__extModem.transmit(port, port, inMsg)
            return
        end
    end
    
    -- the message must be fore someone outside now
    local conId = self:__getConIdStr(msg)
    if not self.__outMessages[conId] then
        self.__outMessages[conId] = {}
    end
    msg.header.conId = conId
    local msgid = self.__extInterface:useMsgId()
    ---@type NetMessage
    local outMsg = {
        origin = self.__extInterface:getIp() --[[@as NetAddress]],
        dest = msg.dest,
        header = msg.header,
        body = msg.body,
        msgid = msgid,
        port = port,
        reply = function() end
    }
    self.__outMessages[conId][msgid] = {
        dest = msg.origin,
        destConId = msg.header.conId,
        msgid = msg.msgid
    }
    self.__extModem.transmit(port, port, outMsg)
end

---
---@package
---@param port number
---@param msg NetMessage
function NAT:__messageHandlerExt(port, msg)
    local sysTime = os.epoch()
    if msg.dest ~= self.__extInterface:getIp() then
        return
    end

    if msg.header.type == net.sockets.NetSocketType then
        ---@cast msg NetSocket.Message
        local socketRecord = self.__sockets[msg.header.destSocketId] ---@type NAT.SocketRecord
        if (msg.origin ~= socketRecord.dest) then
            return
        end
        
        msg.header.destSocketId = socketRecord.originSocketId
        msg.header.destConId = socketRecord.conId
        
        ---@type NetMessage
        local inMsg = {
            origin = msg.origin,
            dest = socketRecord.origin,
            header = msg.header,
            body = msg.body,
            msgid = msg.msgid,
            port = port,
            reply = function () end
        }

        self.__intModem.transmit(port, port, inMsg)
        return
    end

    if msg.header.destConId then
        local inConId = msg.header.destConId
        local msgRecord = self.__outMessages[inConId][msg.msgid] ---@type NAT.MessageRecord
        if msgRecord then
            self.__outMessages[inConId][msg.msgid] = nil

            msg.header.destConId = msgRecord.destConId

            ---@type NetMessage
            local inMsg = {
                origin = msg.origin,
                dest = msgRecord.dest,
                header = msg.header,
                body = msg.body,
                msgid = msgRecord.msgid,
                port = port,
                reply = function () end
            }
            self.__intModem.transmit(port, port, inMsg)
            return
        end
    end

    local rule = nil ---@type NAT.ForwardingRecord?
    if msg.header.domain then
        local r = self:__dbQuery('SELECT * FROM %s WHERE domain = "%s"', FORWARDING_TABLE, msg.header.domain) --[[@as { number: NAT.ForwardingRecord } ]]
        if #r >= 1 then
            for _, rl in pairs(r) do
                if not rl.port then
                    rule = rl
                    break
                elseif rl.port == port then
                    rule = rl
                    break
                end
            end
        end
    else
        local r = self:__dbQuery('SELECT * FROM %s WHERE port = %s', FORWARDING_TABLE, port) --[[@as { number: NAT.ForwardingRecord } ]]
        if #r >= 1 then
            for _, rl in pairs(r) do
                if not rl.domain then
                    rule = rl
                    break
                end
            end
        end
        if not rule then
            r = self:__dbQuery('SELECT * FROM %s', FORWARDING_TABLE, port) --[[@as { number: NAT.ForwardingRecord } ]]
            if #r >= 1 then
                for _, rl in pairs(r) do
                    if not (rl.domain or rl.port) then
                        rule = rl
                        break
                    end
                end
            end
        end
    end
    if rule then
        local destIP = rule.dest
        if type(destIP) ~= 'number' then
            if net.isIPV4(destIP) then
                destIP = net.ipToNumber(destIP)
            else
                destIP = self.controller.dns:resolveLocal(destIP)
                if destIP < 0x0 then
                    self.logger:error('Unable to resolve `%s` for forwarding rule', rule.dest)
                end
            end
        end
        
        local msgid = self.__intInterface:useMsgId()

        ---@type NetMessage
        local inMsg = {
            origin = msg.origin,
            dest = destIP,
            header = msg.header,
            body = msg.body,
            msgid = msgid,
            port = port,
            reply = function() end
        }
        local conId = self:__getConIdStr(inMsg)
        inMsg.header.conId = conId

        ---@type NAT.MessageRecord
        self.__inMessages[conId][msgid] = {
            dest = msg.origin,
            destConId = msg.header.conId,
            msgid = msg.msgid
        }
        self.__intModem.transmit(port, port, inMsg)
        return
    end
end

---@param msg RttpMessage
---@return number code
---@return string contentType
---@return string|table body
---@return RttpMessage.Header? header
function NAT:handleRTTP(msg)
    if msg.header.path == '/nat' then
        local page = net.rtml.createContext(rtmlLoader.loadFile('rtml/nat.rtml'))
        
        local records = self:__dbQuery('SELECT * FROM %s', FORWARDING_TABLE)
        ---@cast records NAT.ForwardingRecord[]
        local y = 4
        for _, record in pairs(records) do
            y = y + 1
            page:addText(2, y, record.domain or '*')
            page:addText(22, y, (record.port .. '') or '*')
            if type(record.dest) == "number" then
                page:addText(30, y, net.ipFormat(record.dest))
            else
                page:addText(30, y, record.dest--[[@as string]])
            end
        end
        return rttp.responseCodes.okay, 'text/plain', page
    end
    return rttp.responseCodes.notFound, 'text/plain', '404 - Unknown page'
end

return NAT