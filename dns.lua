pos.require("net.rttp")
pos.require('net.rtml')
local rtmlLoader = pos.require('net.rtml.rtmlLoader')

---@class DNS: LANController.Service
---@field config LANControllerConfig
---@field interface NetInterface
---@field extInterface NetInterface
---@field private __handlerId number?
local DNS = {}

local DNS_MT = {
    __index = DNS
}

local DNS_TABLE = 'dns'
-- domain: string NOT_NIL, type: string ('A','CNAME','NS') NOT_NIL DEFAULT='A', ip: number?, pointer: string?, ttl: number NOT_NIL
--[[
CREATE TABLE dns ( domain string NOT_NIL, type string NOT_NIL def='A', ip number, pointer string, ttl number NOT_NIL )
]]
local REMOTE_DNS_TABLE = 'remote_dns'
-- domain: string NOT_NIL, type: string ('A','CNAME','NS') NOT_NIL DEFAULT='A', ip: number?, pointer: string?, ttl: number NOT_NIL, time: number NOT_NIL
--[[
CREATE TABLE remote_dns ( domain string NOT_NIL, type string NOT_NIL def='A', ip number, pointer string, ttl number NOT_NIL, time number NOT_NIL )
]]

---@class DNS.DNSRecord
---@field domain string Record domain name
---@field type 'A'|'CNAME'|'NS' Record type
---@field ip number? IP destination of A type records
---@field pointer string? Domain destination of CNAME and NS type records
---@field ttl number Time To Live of record, specified in minutes
---@field time number? Time record was lasted updated

local MSG_TYPE_DNS_GET = 'net.dns.get'
local MSG_TYPE_DNS_GET_RETURN = 'net.dns.get.return'

---@param controller LANController
---@param logger Logger
function DNS.new(controller, logger)
    local o = {}
    setmetatable(o, DNS_MT)
    o:__init__(controller, logger)
    return o
end

---@package
---@param controller LANController
---@param logger Logger
function DNS:__init__(controller, logger)
    self.controller = controller
    self.config = controller.config
    self.logger = logger
    logger.logTime = true
    self.interface = controller.insideInterface
    self.extInterface = controller.outsideInterface
end

---@package
---@param cmd string
---@vararg string|number
function DNS:__dbQuery(cmd, ...)
    return self.controller.dbQuery(self, cmd, ...)
end

function DNS:start()
    self.__handlerId = self.interface:addMsgHandler(function(msg)
        self:__messageHandler(msg)
    end)

    self:__dbQuery("CREATE TABLE IF NOT EXISTS %s ( domain string NOT_NIL, type string NOT_NIL def=\"A\", ip number, pointer string, ttl number NOT_NIL )", DNS_TABLE)
    self:__dbQuery("CREATE TABLE IF NOT EXISTS %s ( domain string NOT_NIL, type string NOT_NIL def=\"A\", ip number, pointer string, ttl number NOT_NIL, time number NOT_NIL )", REMOTE_DNS_TABLE)
end

---@param targetDomain string
---@return DNS.DNSRecord? record
---@return DNS.DNSRecord[]? records
function DNS:__getDNSRecord(targetDomain)
    local sysTime = os.epoch('utc')

    local r = self:__dbQuery('SELECT * FROM %s WHERE domain = "%s"', DNS_TABLE, targetDomain)
    local record = nil ---@type DNS.DNSRecord?
    local records = {} ---@type DNS.DNSRecord[]
    ---@cast r DNS.DNSRecord[]
    if #r == 1 then -- If there was an entry in the lease table
        record = r[1]
        record.time = sysTime
        records = {}
    elseif #r > 1 then
        for i = 1, #r do
            r[1].time = sysTime
            if not record and r[1].type == 'A' then
                record = r[i];
            else
                table.insert(records, r[i])
            end
        end
    else
        r = self:__dbQuery('SELECT * FROM %s WHERE domain = "%s"', REMOTE_DNS_TABLE, targetDomain)
        ---@cast r DNS.DNSRecord[]
        if #r == 1 then
            record = r[1]
            if record.time + (record.ttl * 60 * 1000) < sysTime then
                self:__dbQuery('DELETE FROM %s WHERE domain = "%s"', DNS_TABLE, record.domain)
                record = nil
            end
        else
            for i = 1, #r do
                if r[i].time + (r[i].ttl * 60 * 1000) < sysTime then
                    self:__dbQuery('DELETE FROM %s WHERE domain = "%s" AND type = "%s"', DNS_TABLE, targetDomain, r[1].type)
                else
                    if not record and r[1].type == 'A' then
                        record = r[i];
                    else
                        table.insert(records, r[i])
                    end
                end
            end
        end

        if not record then
            local rsp = self.extInterface:sendSync(net.standardPorts.network, 0xffffffff, MSG_TYPE_DNS_GET,
                { domain = targetDomain })
            if type(rsp) ~= 'string' then
                ---@cast rsp DNS.Message
                if rsp.header.code == 'found' then
                    record = rsp.body.record
                    if not record then
                        record = {
                            domain = rsp.header.hostname,
                            ttl = 60,
                            type = 'A',
                            ip = rsp.origin --[[@as number]],
                        }
                    end
                    record.time = os.epoch('utc')
                    if record.type == 'A' then
                        self:__dbQuery('INSERT INTO %s domain, type, ttl, time, ip VALUES "%s", "%s", %s, %s, %s',
                            REMOTE_DNS_TABLE, record.domain,
                            record.type, record.ttl, record.time, record.ip)
                    else
                        self:__dbQuery('INSERT INTO %s domain, type, ttl, time, pointer VALUES "%s", "%s", %s, %s, %s',
                            REMOTE_DNS_TABLE, record.domain,
                            record.type, record.ttl, record.time, record.pointer)
                    end
                end
            end
        end
    end
    if record then
        if record.type == 'NS' then -- this says we need to go somewhere else to find out the IP
            self.logger:warn('Received NS type record, currently unhandled')
            return nil
        end
    end
    return record, records
end

---
---@package
---@param msg NetMessage
function DNS:__messageHandler(msg)
    if msg.port ~= net.standardPorts.network then
        return
    end

    local sysTime = os.epoch('utc')

    if msg.header.type == MSG_TYPE_DNS_GET then
        local targetDomain = msg.body.domain

        self.logger:info('Record search for `%s` requested', targetDomain)
        local record, records = self:__getDNSRecord(targetDomain)

        if record then
            msg:reply(msg.port, {
                type = MSG_TYPE_DNS_GET_RETURN,
                code = 'found',
                hostname = targetDomain,
            }, {
                ip = record.ip,
                pointer = record.pointer,
                port = '*',
                time = record.time or -1,
                type = record.type,
                record = record,
                records = records
            })
            if record.type == 'A' then
                self.logger:info('Returning A record for `%s` pointing to  %s', targetDomain, net.ipFormat(record.ip))
            elseif record.type == 'CNAME' then
                self.logger:info('Returning CNAME record for `%s` pointing to  `%s`', targetDomain, record.pointer)
            elseif record.type == 'NS' then
                self.logger:info('Returning NS record for `%s` pointing to  `%s`', targetDomain, record.pointer)
            end
        else
            if msg.dest ~= 0xffffffff then -- if it's a direct request, otherwise let someone else respond if able
                msg:reply(msg.port, {
                    type = MSG_TYPE_DNS_GET_RETURN,
                    code = 'not_found',
                    hostname = targetDomain,
                }, {})
            end
            self.logger:info('Could not find record record for `%s`', targetDomain)
        end
    end
end

---@param msg RttpMessage
---@return number code
---@return string contentType
---@return string|table body
---@return RttpMessage.Header? header
function DNS:handleRTTP(msg)
    if msg.header.path == '/dns' then
        local page = net.rtml.createContext(rtmlLoader.loadFile('/os/bin/lan-controller/rtml/dns.rtml'))
        
        local records = self:__dbQuery('SELECT * FROM %s', DNS_TABLE)
        ---@cast records DNS.DNSRecord[]
        local y = 4
        for _, record in pairs(records) do
            y = y + 1
            page:addLink(2, y, record.domain, '/dns/edit/'..record.domain)
            page:addText(18, y, record.type)
            if record.type == 'A' then
                page:addText(24, y, net.ipFormat(record.ip))
            else
                page:addText(24, y, record.pointer)
            end
            page:addText(45, y, record.ttl..'')
        end
        return rttp.responseCodes.okay, 'table/rtml', page.elements
    elseif msg.header.path:start('/dns/edit/') then
        local domain = msg.header.path:split('/')[4]
        local r = self:__dbQuery('SELECT * FROM %s WHERE domain = "%s"', DNS_TABLE, domain)
        if #r == 0 then
            return rttp.responseCodes.badRequest, 'table/rtml',
                { { type = "TEXT", x = 1, y = 1, text = "Unknown Record" }, { type = "LINK", x = 2, y = 2, text = "Return to DNS Panel", href = "/dns" } }
        end
        local record = r[1] ---@type DNS.DNSRecord
        if msg.header.method == 'GET' then
            local editPage = net.rtml.createContext(rtmlLoader.loadFile('/os/bin/lan-controller/rtml/dns/edit.rtml'))
            editPage:addText(2, 3, ('Domain: %s'):format(record.domain))
            editPage:addText(2, 4, ('Type: (%s)'):format(record.type))
            editPage:addText(2, 6, ('Pointer: (%s)'):format(record.pointer or net.ipFormat(record.ip)))
            editPage:addText(2, 8, ('TTL: (%s)'):format(record.ttl))
            return rttp.responseCodes.okay, 'table/rtml', editPage.elements
        elseif msg.body.type == 'BUTTON_SUBMIT' then
            local rt = msg.body.vals

            if rt.type ~= '' and rt.type ~= record.type then
                if rt.pointer == '' then
                    return rttp.responseCodes.badRequest, 'text/plain', 'Change of record type must include new pointer'
                end
                if rt.type == 'A' then
                    if net.isIPV4(rt.pointer) then
                        rt.pointer = net.ipToNumber(rt.pointer) --[[@as number]]
                    else
                        rt.pointer = tonumber(rt.pointer)
                        if not rt.pointer then
                            return rttp.responseCodes.badRequest, 'text/plain', 'Malformed IP pointer'
                        end
                    end
                    record.ip = rt.pointer
                    record.pointer = ''
                    self:__dbQuery('UPDATE %s SET type="%s", ip=%s, pointer=nil WHERE domain = "%s"', DNS_TABLE,
                        rt.type, rt.pointer, domain)
                else
                    record.pointer = rt.pointer --[[@as string]]
                    record.ip = -1
                    self:__dbQuery('UPDATE %s SET type="%s", pointer="%s", ip=nil WHERE domain = "%s"', DNS_TABLE,
                        rt.type, rt.pointer, domain)
                end
            elseif rt.pointer ~= '' then
                if record.type == 'A' then
                    if net.isIPV4(rt.pointer) then
                        rt.pointer = net.ipToNumber(rt.pointer) --[[@as number]]
                    else
                        rt.pointer = tonumber(rt.pointer)
                        if not rt.pointer then
                            return rttp.responseCodes.badRequest, 'text/plain', 'Malformed IP pointer'
                        end
                    end
                    if rt.pointer ~= record.ip then
                        self:__dbQuery('UPDATE %s SET ip = %s WHERE domain = "%s"', DNS_TABLE, rt.pointer, domain)
                    end
                elseif rt.pointer ~= record.pointer then
                    self:__dbQuery('UPDATE %s SET pointer = "%" WHERE domain = "%s"', DNS_TABLE, rt.pointer, domain)
                end
            end
            if rt.ttl ~= '' and rt.ttl ~= record.ttl then
                self:__dbQuery('UPDATE %s SET ttl = %s WHERE domain = "%s"', DNS_TABLE, tonumber(rt.ttl) or record.ttl,
                    domain)
            end
            return rttp.responseCodes.okay, 'text/plain', 'Updated'
        elseif msg.body.type == 'BUTTON_PUSH' then
            if msg.header.path:ends('/remove') then
                self:__dbQuery('DELETE FROM %s WHERE domain = "%s"', DNS_TABLE, domain)
                return  rttp.responseCodes.movedTemporarily, 'text/plain', 'Record deleted', { redirect = '/dns' }
            end
            return rttp.responseCodes.badRequest, 'text/plain', 'Unknown action'
        end
    elseif msg.header.path == '/dns/new' then
        if msg.header.method == 'GET' then
            return rttp.responseCodes.okay, 'table/rtml', rtmlLoader.loadFile('/os/bin/lan-controller/rtml/dns/new.rtml')
        else
            local rt = msg.body.vals
            if #self:__dbQuery('SELECT pointer FROM %s WHERE domain = "%s"', DNS_TABLE, rt.domain) > 0 then
                return rttp.responseCodes.movedTemporarily, 'text/plain', 'Record with domain already exists',
                    { redirect = '/dns/alreadyExists' }
            end
            if rt.type == 'A' then
                local ip = rt.pointer
                if tonumber(ip) then
                    ip = tonumber(ip)
                elseif net.isIPV4(ip) then
                    ip = net.ipToNumber(ip)
                else
                    return rttp.responseCodes.badRequest, 'text/plain', 'Pointer must be valid IP'
                end
                self:__dbQuery('INSERT INTO %s domain, type, ip, ttl VALUES "%s", "A", %s, %s', DNS_TABLE, rt.domain, ip,
                    rt.ttl)
            else
                self:__dbQuery('INSERT INTO %s domain, type, pointer, ttl VALUES "%s", "%s", "%s", %s', DNS_TABLE,
                    rt.domain, rt.type, rt.pointer, rt.ttl)
            end
            return rttp.responseCodes.movedTemporarily, 'text/plain', 'Record created', {redirect = '/dns'}
        end
    elseif msg.header.path == '/dns/alreadyExists' then
        return rttp.responseCodes.okay, 'text/plain', 'Record with domain also exists'
    end
    return rttp.responseCodes.notFound, 'text/plain', '404 - Unknown page'
end

---@param domain string
---@return NetAddress ip
function DNS:resolveLocal(domain)
    local r = self:__dbQuery('SELECT * FROM %s WHERE domain = "%s"', DNS_TABLE, domain)
    if #r == 1 then
        local record = r[1] ---@type DNS.DNSRecord
        if record.type == 'A' then
            return record.ip
        elseif record.type == 'CNAME' then
            return self:resolveLocal(record.pointer)
        elseif record.type == 'NS' then
            self.logger:warn('Tried to resolve NS type record, currently unhandled')
            return -1
        end
    end
    return -1
end

---Add a record to the DNS
---@param domain string
---@param recordType 'A'|'CNAME
---@param value number|string
---@param ttl number?
function DNS:addRecord(domain, recordType, value, ttl)
    expect(1, domain, "string")
    expect(4, ttl, "number", "nil")

    ttl = ttl or (60 * 24)
    if recordType == 'A' then
        if type(value) == "string" then
            if not net.isIPV4(value) then
                error('Expected value to be a valid IP address for A type records, was ' .. value, 2)
            end
            value = net.ipToNumber(value)
        end
        if type(value) ~= "number" then
            error('Expected value to be a valid IP address for A type records, was ' .. type(value), 2)
        end
        self.logger:info('Adding A record for %s pointing to %s', domain, net.ipFormat(value))
        self:__dbQuery('INSERT INTO %s domain, type, ip, ttl VALUES "%s", "A", %d, %d', DNS_TABLE, domain, value, ttl)
    elseif recordType == 'CNAME' then
        if type(value) ~= "string" then
            error('Expected value to be a string for CNAME type records, was ' .. type(value), 2)
        end
        self.logger:info('Adding CNAME record for %s pointing to %s', domain, value)
        self:__dbQuery('INSERT INTO %s domain, type, pointer, ttl VALUES "%s", "CNAME", "%s", %d', DNS_TABLE, domain,
            value, ttl)
    else
        error('Unknown record type; Expected `A` or `CNAME` got "' .. recordType .. '"', 2)
    end
end

---Add or update a record to the DNS
---@param domain string
---@param recordType 'A'|'CNAME
---@param value number|string
---@param ttl number?
function DNS:updateRecord(domain, recordType, value, ttl)
    expect(1, domain, "string")
    expect(4, ttl, "number", "nil")

    local r = self:__dbQuery('SELECT ip FROM %s WHERE domain = "%s" AND type = "%s"', DNS_TABLE, domain, recordType)
    local add = #r == 0

    ttl = ttl or (60 * 24)
    if recordType == 'A' then
        if type(value) == "string" then
            if not net.isIPV4(value) then
                error('Expected value to be a valid IP address for A type records, was '..value, 2)
            end
            value = net.ipToNumber(value)
        end
        if type(value) ~= "number" then
            error('Expected value to be a valid IP address for A type records, was ' .. type(value), 2)
        end
        if add then
            self.logger:info('Adding A record for %s pointing to %s', domain, net.ipFormat(value))
            self:__dbQuery('INSERT INTO %s domain, type, ip, ttl VALUES "%s", "A", %d, %d', DNS_TABLE, domain, value, ttl)
        else
            self.logger:info('Updating A record for %s pointing to %s', domain, net.ipFormat(value))
            self:__dbQuery('UPDATE %s SET ip=%d, ttl=%d WHERE domain = "%s" AND type = "A"', DNS_TABLE, value, ttl, domain)
        end
    elseif recordType == 'CNAME' then
        if type(value) ~= "string" then
            error('Expected value to be a string for CNAME type records, was ' .. type(value), 2)
        end
        if add then
            self.logger:info('Adding CNAME record for %s pointing to %s', domain, value)
            self:__dbQuery('INSERT INTO %s domain, type, pointer, ttl VALUES "%s", "CNAME", "%s", %d', DNS_TABLE, domain, value, ttl)
        else
            self.logger:info('Updating CNAME record for %s pointing to %s', domain, value)
            self:__dbQuery('UPDATE %s SET pointer="%s", ttl=%d WHERE domain = "%s" AND type = "CNAME"', DNS_TABLE, value, ttl, domain)
        end
    else
        error('Unknown record type; Expected `A` or `CNAME` got "'..recordType..'"', 2)
    end
end

return DNS