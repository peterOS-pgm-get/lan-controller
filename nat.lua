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
---@field private __intMessages { [string]: boolean } Table of internal messages that have been processed by origin string and msgId (origin#msgid)
---@field private __extMessages { [string]: boolean } Table of external messages that have been processed by origin string and msgId (origin#msgid)
---@field private __outMessages { [NetAddress]: { [number]: NAT.MessageRecord } }
---@field private __conIdTable { [string]: number }
---@field private __inMessages { [NetAddress]: { [number]: NAT.MessageRecord } }
---@field private __sockets { [number]: NAT.SocketRecord }
---@field private __socketsByOrigin { [NetAddress]: { [NetAddress]: number } }
local NAT = {}

local NAT_MT = {
    __index = NAT
}

---Forwarding rule table
--- - `domain`: `string` NOT_NIL
--- - `port`: `number` NOT_NIL
--- - `dest`: `string` NOT_NIL
local FORWARDING_TABLE = 'forwarding'
--[[
CREATE TABLE forwarding ( domain string NOT_NIL, port number NOT_NIL, dest string NOT_NIL )
]]

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
    logger.logTime = true

    self.__intInterface = controller.insideInterface
    self.__intModem = controller.insideInterface:getModem()
    self.__extInterface = controller.outsideInterface
    self.__extModem = controller.outsideInterface:getModem()

    self.__intMessages = {}
    self.__extMessages = {}
    self.__outMessages = {}
    self.__inMessages = {}
    self.__conIdTable = {}
end

---@package
---@param cmd string
---@vararg string|number
function NAT:__dbQuery(cmd, ...)
    return self.controller.dbQuery(self, cmd, ...)
end

local function getMsgIdentifier(msg)
    local id = net.getOriginString(msg)
    return id .. '#' .. msg.msgid
end

function NAT:start()
    self.logger:info('Starting NAT')
    self.__handlerId = pos.addEventHandler(function(event)
        local _, side, port, _, msg = table.unpack(event)
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
    for _,port in pairs(net.standardPorts) do
        self.__intInterface:open(port)
        self.__extInterface:open(port)
    end
end

function NAT:__getParingString(msg)
    local originStr = net.getOriginString(msg)
    local destStr = msg.dest
    if msg.header.domain then
        destStr = msg.header.domain
    elseif msg.header.destConId then
        destStr = destStr .. ':' .. msg.header.destConId
    end
    
    return originStr .. '-' .. destStr
end

---@param msg NetMessage
---@return number
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
        self.__conIdTable[paring] = conId
    end
    return conId
end

local function copyObject(src)
    if type(src) ~= "table" then
        return src
    end
    local o = {}
    for k,v in pairs(src) do
        o[k] = copyObject(v)
    end
    return o
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
    self.logger:debug('Got message for pass out')
    self.logger:debug(net.stringMessage(msg))

    if msg.header.type == net.sockets.NetSocketType then -- is a socket message
        ---@cast msg NetSocket.Message
        local socketID = self.__socketsByOrigin[msg.origin][msg.dest]
        if not socketID then
            socketID = self.__extInterface:useMsgId()
            self.__socketsByOrigin[msg.origin][msg.dest] = socketID
        end
        self.__sockets[socketID] = {
            origin = msg.origin,
            conId = msg.header.conId,
            originSocketId = msg.header.originSocketId,
            dest = msg.dest
        }
        msg.header.destSocketId = socketID
    end

    if msg.header.conId then -- from an existing connection
        self.logger:debug('- Message had connection ID: %d', msg.header.conId)
        local outConId = msg.header.conId
        if not self.__inMessages[outConId] then
            self.logger:warn('??')
            return
        end
        local msgRecord = self.__inMessages[outConId][msg.msgid]
        if msgRecord then
            self.__outMessages[outConId][msg.msgid] = nil

            msg.header.destConId = msgRecord.destConId
            msg.header.conId = nil

            ---@type NetMessage
            local outMsg = copyObject({
                origin = self.__extInterface:getIp() --[[@as NetAddress]],
                dest = msg.dest,
                header = msg.header,
                body = msg.body,
                msgid = msg.msgid,
                port = port,
                reply = function() end
            })
            self.logger:debug('Passing connection message out: %s:%d C#%d #%d', net.ipFormat(outMsg.dest), port, outConId,
                outMsg.msgid)
            -- self.__extModem.transmit(port, port, outMsg)
            self.__extInterface:sendRaw(outMsg, port)
            return
        else
            self.logger:warn('Message had connection ID, but message id didn\'t exist in table')
        end
    end

    -- the message must be for someone outside now
    local conId = self:__getConIdStr(msg)
    if not self.__outMessages[conId] then
        self.__outMessages[conId] = {}
    end
    msg.header.conId = conId
    -- local msgid = self.__extInterface:useMsgId()
    local msgid = msg.msgid
    ---@type NetMessage
    local outMsg = copyObject({
        origin = self.__extInterface:getIp() --[[@as NetAddress]],
        dest = msg.dest,
        header = msg.header,
        body = msg.body,
        msgid = msgid,
        port = port,
        reply = function() end
    })
    self.__outMessages[conId][msgid] = {
        dest = msg.origin,
        destConId = msg.header.conId,
        msgid = msg.msgid
    }
    self.__extInterface:sendRaw(outMsg, port)
    -- self.__extModem.transmit(port, port, outMsg)
    self.logger:debug('Passing message out: %s:%d #%d', net.ipFormat(outMsg.dest), port, outMsg.msgid)
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
    self.logger:debug('Got message for pass in: port %d, %s', msg.port, msg.header.type)
    self.logger:debug(net.stringMessage(msg))

    if msg.header.type == net.sockets.NetSocketType then
        ---@cast msg NetSocket.Message
        local socketRecord = self.__sockets[msg.header.destSocketId] ---@type NAT.SocketRecord
        if (msg.origin ~= socketRecord.dest) then
            return
        end
        
        msg.header.destSocketId = socketRecord.originSocketId
        msg.header.destConId = socketRecord.conId
        
        ---@type NetMessage
        local inMsg = copyObject({
            origin = msg.origin,
            dest = socketRecord.origin,
            header = msg.header,
            body = msg.body,
            msgid = msg.msgid,
            port = port,
            reply = function () end
        })

        -- self.__intModem.transmit(port, port, inMsg)
        self.__intInterface:sendRaw(inMsg, port)
        self.logger:debug('Passed message in on existing socket to %s', net.ipFormat(inMsg.dest))
        return
    end

    if msg.header.destConId then
        local inConId = msg.header.destConId
        local msgRecord = self.__outMessages[inConId][msg.msgid] ---@type NAT.MessageRecord
        if msgRecord then
            self.__outMessages[inConId][msg.msgid] = nil

            msg.header.destConId = msgRecord.destConId

            ---@type NetMessage
            local inMsg = copyObject({
                origin = msg.origin,
                dest = msgRecord.dest,
                header = msg.header,
                body = msg.body,
                msgid = msg.msgid,
                port = port,
                reply = function () end
            })
            -- self.__intModem.transmit(port, port, inMsg)
            self.__intInterface:sendRaw(inMsg, port)
            self.logger:debug('Passed message in on existing connection to %s', net.ipFormat(inMsg.dest))
            return
        end
    end

    local rule = nil ---@type NAT.ForwardingRecord?
    --[[
        Our check order is:
        1) domain & port
        2) domain & any port
        3) any domain & port
        4) any domain & any port
    ]]
    if msg.header.domain then -- only bother checking domain if we have it
        local r = self:__dbQuery('SELECT * FROM %s WHERE domain = "%s" AND port = %d', FORWARDING_TABLE, msg.header.domain, port) --[[@as { [number]: NAT.ForwardingRecord } ]]
        if #r >= 1 then
            rule = r[1]
        else
            r = self:__dbQuery('SELECT * FROM %s WHERE domain = "%s" AND port = -1', FORWARDING_TABLE, msg.header.domain) --[[@as { [number]: NAT.ForwardingRecord } ]]
            if #r >= 1 then
                rule = r[1]
            end
        end
    end
    if not rule then
        local r = self:__dbQuery('SELECT * FROM %s WHERE domain = "*" AND port = %s', FORWARDING_TABLE, port) --[[@as { [number]: NAT.ForwardingRecord } ]]
        if #r >= 1 then
            rule = r[1]
        end
    end
    if not rule then
        local r = self:__dbQuery('SELECT * FROM %s WHERE domain = "*" AND port = -1', FORWARDING_TABLE) --[[@as { [number]: NAT.ForwardingRecord } ]]
        if #r >= 1 then
            rule = r[1]
        end
    end

    if not rule then
        return -- early return for no rule
    end

    local destIP = rule.dest
    if type(destIP) ~= 'number' then
        if net.isIPV4(destIP) then
            destIP = net.ipToNumber(destIP)
        else
            destIP = self.controller.dns:resolveLocal(destIP)
            if destIP < 0x0 then
                self.logger:error('Unable to resolve destination `%s` for forwarding rule', rule.dest)
                return
            end
        end
    end
    
    -- local msgid = self.__intInterface:useMsgId()
    local msgid = msg.msgid

    ---@type NetMessage
    local inMsg = copyObject({
        origin = msg.origin,
        dest = destIP,
        header = msg.header,
        body = msg.body,
        msgid = msgid,
        port = port,
        reply = function() end
    })
    local conId = self:__getConIdStr(inMsg)
    inMsg.header.conId = conId

    if not self.__inMessages[conId] then
        self.__inMessages[conId] = {}
    end
    ---@type NAT.MessageRecord
    self.__inMessages[conId][msgid] = {
        dest = msg.origin,
        destConId = msg.header.conId,
        msgid = msg.msgid
    }
    -- self.__intModem.transmit(port, port, inMsg)
    self.__intInterface:sendRaw(inMsg, port)
    self.logger:debug('Passed message in on rule to %s with new connection ID %d', net.ipFormat(inMsg.dest), conId)
end

---@param domain string?
---@param port number?
---@param dest string|number
function NAT:addRule(domain, port, dest)
    if not (domain or port) then
        error('Must specify at least domain or port')
    end

    expect(1, domain, "string", "nil")
    domain = domain or '*'
    expect(2, port, "number", "nil")
    expect(3, dest, "number", "string")
    local destStr = dest
    if type(dest) == "string" then
        destStr = '"'..dest..'"'
    end

    if port then
        local r = self:__dbQuery('SELECT dest FROM %s WHERE domain = "%s" AND port = %d', FORWARDING_TABLE, domain, port)
        if #r == 0 then
            self.logger:info('Adding rule for %s:%d pointing to %s', domain, port, dest)
            self:__dbQuery('INSERT INTO %s domain, port, dest VALUES "%s", %d, %s', FORWARDING_TABLE, domain, port, destStr)
        else
            self.logger:info('Updating rule for %s:%d pointing to %s', domain, port, dest)
            self:__dbQuery('UPDATE %s SET dest=%s WHERE domain = "%s" AND port = %d', FORWARDING_TABLE, destStr, domain, port)
        end
    else
        local r = self:__dbQuery('SELECT dest FROM %s WHERE domain = "%s" AND port = -1', FORWARDING_TABLE, domain)
        if #r == 0 then
            self.logger:info('Adding rule for %s:* pointing to %s', domain, port, dest)
            self:__dbQuery('INSERT INTO %s domain, port, dest VALUES "%s", -1, %s', FORWARDING_TABLE, domain, destStr)
        else
            self.logger:info('Updating rule for %s:* pointing to %s', domain, port, dest)
            self:__dbQuery('UPDATE %s SET dest=%s WHERE domain = "%s" AND port = -1', FORWARDING_TABLE, destStr, domain)
        end
    end
end

---@param msg RttpMessage
---@return number code
---@return string contentType
---@return string|table body
---@return RttpMessage.Header? header
function NAT:handleRTTP(msg)
    local path = msg.header.path or '/'
    if path == '/nat' then
        local page = net.rtml.createContext(rtmlLoader.loadFile('/os/bin/lan-controller/rtml/nat.rtml'))
        
        local records = self:__dbQuery('SELECT * FROM %s', FORWARDING_TABLE)
        ---@cast records NAT.ForwardingRecord[]
        local y = 4
        for _, record in pairs(records) do
            y = y + 1
            page:addText(2, y, record.domain or '*')
            page:addText(22, y, (record.port or '*') .. '')
            if type(record.dest) == "number" then
                page:addText(30, y, net.ipFormat(record.dest))
            else
                page:addText(30, y, record.dest --[[@as string]])
            end
            local id = (record.domain or '-') .. '_' .. (record.port or '-')
            page:addLink(45, y, 'Edit', '/nat/edit/'..id)
        end
        
        page:addLink(2, y+2, 'New Rule', '/nat/new')
            
        return rttp.responseCodes.okay, 'table/rtml', page.elements
    elseif path:start('/nat/remove/') then
        local page = net.rtml.createContext()

        local id = path:sub(13):split('_')
        local domain = (id[1] ~= '-' and id[1]) or '*'
        local port = (id[2] ~= '-' and tonumber(id[2])) or -1
        
        self:__dbQuery('DELETE FROM %s WHERE domain = "%s" AND port = %d', FORWARDING_TABLE, domain, port)
        page:addText(1,2, 'Rule deleted')
        page: addLink(1,4, 'Return to NAT panel', '/nat')

        return rttp.responseCodes.okay, 'table/rtml', page.elements
    elseif path:start'/nat/edit/' then
        local id = path:sub(11):split('_')
        local domain = (id[1] ~= '-' and id[1]) or '*'
        local port = (id[2] ~= '-' and tonumber(id[2])) or -1

        if msg.header.method == 'GET' then
            local page = net.rtml.createContext(rtmlLoader.loadFile('/os/bin/lan-controller/rtml/nat/edit.rtml'))
            page:addText(3, 5, domain)
            page:addText(3, 7, (port ~= 1 and (port..'') or '*'))
            return rttp.responseCodes.okay, 'table/rtml', page.elements
        elseif msg.header.method == 'POST' then
            if msg.body.type == net.rtml.BUTTON_ACTION_SUBMIT then
                local rt = msg.body.vals
                local dest = tonumber(rt.dest) or rt.dest

                self:addRule(domain, port, dest)

                return rttp.responseCodes.movedTemporarily, 'text/plain', 'Rule modified', { redirect = '/nat' }
            else
                self:__dbQuery('DELETE FROM %s WHERE domain = "%s" AND port = %d', FORWARDING_TABLE, domain, port)
                
                return rttp.responseCodes.movedTemporarily, 'text/plain', 'Rule deleted', { redirect = '/nat' }
            end
        end
    elseif path == '/nat/new' then
        if msg.header.method == 'GET' then
            return rttp.responseCodes.okay, 'table/rtml', rtmlLoader.loadFile('/os/bin/lan-controller/rtml/nat/new.rtml')
        elseif msg.header.method == 'POST' then
            local rt = msg.body.vals
            local domain = rt.domain or '*'
            local port = tonumber(rt.port) or -1
            local dest = tonumber(rt.dest) or rt.dest

            self:addRule(domain, port, dest)

            return rttp.responseCodes.movedTemporarily, 'text/plain', 'Rule added', { redirect = '/nat' }
        end
    end
    return rttp.responseCodes.notFound, 'text/plain', '404 - Unknown page'
end

return NAT