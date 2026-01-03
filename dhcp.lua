pos.require("net.rttp")
pos.require('net.rtml')
local rtmlLoader = pos.require('net.rtml.rtmlLoader')

---@class DHCP: LANController.Service
---@field config LANControllerConfig
---@field interface NetInterface
---@field __handlerId number?
---@field __tempLeases table<string, DHCP.LeaseRecord>
local DHCP = {}

local DHCP_MT = {
    __index = DHCP
}

---Lease DB table
--- - `owner`: `string` PRIMARY_KEY
--- - `ip`: `number` NOT_NIL
--- - `time`: `number` NOT_NIL
--- - `hostname`: `string?`
local LEASE_TABLE = 'ip_lease'
--[[
lan-controller
CREATE TABLE ip_lease ( owner string PRIMARY_KEY, ip number NOT_NIL, time number NOT_NIL, hostname string );
]]


---@class DHCP.LeaseRecord
---@field owner string HW address of device
---@field ip number Assigned IP address of device
---@field time number Lease expiation time
---@field hostname string? *(Optional)* Hostname for device

local MSG_TYPE_IP_REQUEST = 'net.ip.req'
local MSG_TYPE_IP_REQUEST_RETURN = 'net.ip.req.return'
local MSG_TYPE_IP_ACCEPT = 'net.ip.acp'
local MSG_TYPE_IP_ACCEPT_RETURN = 'net.ip.acp.return'
local MSG_TYPE_IP_RENEW = 'net.ip.renew'
local MSG_TYPE_IP_RENEW_RETURN = 'net.ip.renew.return'

---@param controller LANController
---@param logger Logger
function DHCP.new(controller, logger)
    local o = {}
    setmetatable(o, DHCP_MT)
    o:__init__(controller, logger)
    return o
end

---@package
---@param controller LANController
---@param logger Logger
function DHCP:__init__(controller, logger)
    self.controller = controller
    self.config = controller.config
    self.logger = logger
    logger.logTime = true
    self.interface = controller.insideInterface
    self.__tempLeases = {}
end

function DHCP:start()
    self.logger:info("Starting DHCP service")
    self.__handlerId = self.interface:addMsgHandler(function(msg)
        local s, e = pcall(function()
            self:__messageHandler(msg)
        end)
        if not s then
            self.logger:error('Handler error: %s', e)
        end
    end)
end

---@package
---@param cmd string
---@vararg string|number
function DHCP:__dbQuery(cmd, ...)
    self.logger:debug('executing DB query: %s', cmd)
    return self.controller.dbQuery(self, cmd, ...)
end

---
---@package
---@param msg NetMessage
function DHCP:__messageHandler(msg)
    if msg.port ~= net.standardPorts.network then
        return
    end

    local sysTime = os.epoch('utc')
    self.logger:debug('Received message: %s', msg.header.type)

    if msg.header.type == MSG_TYPE_IP_REQUEST then
        if (type(msg.origin) ~= "string") then
            self.logger:warn('Asked for IP, but requester already had IP; Skipping')
            return
        end
        self.logger:debug('Received IP request from %s', msg.origin)

        local r = self:__dbQuery('SELECT * FROM %s WHERE owner="%s"', LEASE_TABLE, msg.origin)
        ---@cast r DHCP.LeaseRecord[]
        if #r == 1 then -- If there was an entry in the lease table
            self.logger:debug('Found existing lease, checking expiration . . .')
            local lease = r[1] ---@type DHCP.LeaseRecord

            local extend = lease.time == -1 or lease.time > sysTime

            if not extend then
                r = self:__dbQuery('SELECT owner, time FROM %s WHERE ip = %d', LEASE_TABLE, lease.ip)
                ---@cast r DHCP.LeaseRecord[]
                if #r == 1 then -- no one else is using it, so let re-issue it
                    extend = true
                else
                    extend = true -- set to true here, so if there is no one currently using it, we will re-issue
                    for i = 1, #r do
                        local l = r[i]
                        if l.owner ~= msg.origin and (l.time == -1 or l.time < sysTime) then -- someone else had a current claim to it
                            self:__dbQuery('DELETE FROM %s WHERE owner = "%s"', LEASE_TABLE, msg.origin)
                            extend = false
                            break
                        end
                    end
                end
            end

            if extend then
                self.logger:debug('Returning existing lease: %s', net.ipFormat(lease.ip))
                self.logger:debug('  Was for %s', lease.owner)
                lease.time = sysTime + (8.64e7 * 365)
                if msg.body.hostname ~= nil and self.controller.config.assignLANHostname then
                    self.controller.dns:updateRecord(msg.body.hostname..'.lan', 'A', lease.ip);
                end
                self:__dbQuery('UPDATE %s SET time = %d WHERE owner = "%s"', LEASE_TABLE, lease.time, msg.origin)
                msg:reply(net.standardPorts.network, {
                        type = MSG_TYPE_IP_REQUEST_RETURN
                    },
                    {
                        ip = lease.ip,
                        mask = self.config.subnetMask,
                        time = lease.time,
                    }
                )
                self.__tempLeases[lease.owner] = {
                    owner = lease.owner,
                    ip = lease.ip,
                    time = lease.time,
                    hostname = msg.body.hostname,
                    renew = true
                }
                self.logger:debug('Req end;')
                return
            else
                self.logger:info('Existing lease had expired for %s', net.ipFormat(lease.ip))
            end
        end

        -- Create a new lease
        local lease = { --- @type DHCP.LeaseRecord
            owner = msg.origin --[[@as string]],
            ip = self:__generateIP(),
            time = sysTime + (8.64e7 * 365),
            hostname = msg.body.hostname
        }
        -- self.logger:debug('Creating new lease: %s', net.ipFormat(lease.ip))

        --- @TODO Check it's not in use?

        self.logger:info('Tendering ip %s to %s', net.ipFormat(lease.ip), lease.owner)

        msg:reply(net.standardPorts.network, { type = MSG_TYPE_IP_REQUEST_RETURN }, {
            ip = lease.ip,
            mask = self.config.subnetMask,
            time = lease.time
        })
        self.__tempLeases[lease.owner] = lease
    elseif msg.header.type == MSG_TYPE_IP_ACCEPT then
        local lease = self.__tempLeases[ msg.origin --[[@as string]] ]
        if not lease then
            --- @TODO probably should do something more here
            self.logger:warn("Received IP accept, but had no pending lease ...")
            self.logger:debug("- %s", msg.origin)
            return
        end
        self.logger:info('IP accepted by %s', lease.owner)
        msg:reply(net.standardPorts.network, { type = MSG_TYPE_IP_ACCEPT_RETURN }, {
            ip = lease.ip,
            mask = self.config.subnetMask,
            addrTbl = {} -- vestigial
        })
        -- self.logger:debug('check2: %s %s %s', type(lease.owner), type(lease.ip), type(lease.time))
        -- self.logger:debug('check2b: %s %s %s', tostring(lease.owner), tostring(lease.ip), tostring(lease.time))
        if not lease.renew then
            self:__dbQuery('INSERT INTO %s owner, ip, time VALUES "%s", %d, %d', LEASE_TABLE, lease.owner, lease.ip, lease.time)
        end
        if lease.hostname then
            self:__dbQuery('UPDATE %s SET hostname = "%s" WHERE owner = "%s"', LEASE_TABLE, lease.hostname, lease.owner)
            self.controller.dns:updateRecord(lease.hostname..'.lan', 'A', lease.ip);
        end
        -- self.logger:debug('check3')
        self.__tempLeases[ msg.origin --[[@as string]] ] = nil -- remove it from temp lease table
    elseif msg.header.type == MSG_TYPE_IP_RENEW then
        local r = self:__dbQuery('SELECT * FROM %s WHERE ip = %d', LEASE_TABLE, msg.origin) -- or we could do it w/ HWAddr from body (`body.hwaddr`)
        ---@cast r DHCP.LeaseRecord[]
        local lease = r[1]
        if #r == 0 then -- they don't have a lease with us
            --- @TODO probably should do something here
            return
        elseif #r > 1 then -- How did this happen? But let's handle it some what gracefully
            for i=1, #r do -- go till we find one that belongs to the right person
                if r[i].owner == msg.body.hwaddr then
                    lease = r[i]
                    break
                end
            end
        end

        lease.time = sysTime + (8.64e7 * 365)
        self:__dbQuery('UPDATE %S SET time = %d', LEASE_TABLE, lease.time)
        msg:reply(net.standardPorts.network, { type = MSG_TYPE_IP_RENEW_RETURN }, {
            action = 'renewed',
            ip = lease.ip,
            mask = self.config.subnetMask,
            time = lease.time,
            addrTbl = {} -- Vestigial
        })
    end
end

---@param msg RttpMessage
---@return number code
---@return string contentType
---@return string|table body
---@return RttpMessage.Header? header
function DHCP:handleRTTP(msg)
    if msg.header.path == '/dhcp' then
        local page = net.rtml.createContext(rtmlLoader.loadFile('/os/bin/lan-controller/rtml/dhcp.rtml'))
        
        local leases = self:__dbQuery('SELECT * FROM %s', LEASE_TABLE)
        ---@cast leases DHCP.LeaseRecord[]
        local y = 4
        for _, lease in pairs(leases) do
            y = y + 1
            page:addText(2, y, net.ipFormat(lease.ip))
            page:addText(18, y, os.date('%m/%d-%H:%M', lease.time / 1000)..'')
            page:addText(30, y, lease.owner)
            if lease.hostname then
                y = y + 1
                page:addText(10, y, lease.hostname)
            end
        end
        return rttp.responseCodes.okay, 'table/rtml', page.elements
    end
    return rttp.responseCodes.notFound, 'text/plain', '404 - Unknown page'
end

function DHCP.validAddress(ip)
    if ip < 0x0 or ip > 0xffffffff then -- not in IPV4 range
        return false
    end
    if ip >= 0xa9fe0000 and ip <= 0xa9feffff then -- not link local 169.254.0.0/16
        return false
    end
    if ip >= 0xe0000000 and ip <= 0xef000000 then -- not multicast 224.0.0.0/4
        return false
    end
    if ip >= 0x7f000000 and ip <= 0x7fffffff then -- not loopback 127.0.0.0/8
        return false
    end
    return true
end

function DHCP:__generateIP()
    self.logger:debug('Generating new IP . . .')
    self.logger:debug('= base: %s (%d)', net.ipFormat(self.config.baseAddr), self.config.baseAddr)
    self.logger:debug('= mask: %s (%d)', net.ipFormat(self.config.subnetMask), self.config.subnetMask)
    local ip = math.random(2, 0xffffffff - self.config.subnetMask - 1)
    ip = ip + self.config.baseAddr

    -- Get a table of all currently assigned IPs
    local r = self:__dbQuery('SELECT ip FROM %s', LEASE_TABLE) ---@type DHCP.LeaseRecord[]
    local ips = {}
    for i = 1, #r do
        ips[r[i]] = true
    end

    local i = 0
    self.logger:debug('- Trying %s', net.ipFormat(ip))
    while (not DHCP.validAddress(ip)) or ips[ip] do -- Do while invalid OR is currently assigned
        ip = math.random(2, 0xffffffff - self.config.subnetMask - 1)
        self.logger:debug('- Trying %s', net.ipFormat(ip))
        ip = ip + self.config.baseAddr
        i = i + 1
        if i > 1e5 then
            error('Too many attempts to generate IP')
        end
        if i % 50 == 0 then
            sleep(0)
        end
    end
    self.logger:debug('Generated IP %s', net.ipFormat(ip))
    return ip
end

return DHCP