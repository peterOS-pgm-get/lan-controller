pos.require("net.rttp")
pos.require('net.rtml')
local rtmlLoader = pos.require('net.rtml.rtmlLoader')

---@class DHCP: LANController.Service
---@field config LANControllerConfig
---@field interface NetInterface
---@field __handlerId number?
local DHCP = {}

local DHCP_MT = {
    __index = DHCP
}

local LEASE_TABLE = 'ip_lease'
-- owner: string PRIMARY_KEY, ip: number NOT_NIL, time: number NOT_NIL, hostname: string?

---@class DHCP.LeaseRecord
---@field owner string HW address of device
---@field ip number Assigned IP address of device
---@field time number Lease expiation time
---@field hostname string? *(Optional)* Hostname for device

local MSG_TYPE_IP_REQUEST = 'net.ip.req'
local MSG_TYPE_IP_REQUEST_RETURN = 'net.ip.req.return'

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
    self.interface = controller.insideInterface
end

function DHCP:start()

    self.__handlerId = self.interface:addMsgHandler(function (msg)
        self:__messageHandler(msg)
    end)
end

---@package
---@param cmd string
---@vararg string|number
function DHCP:__dbQuery(cmd, ...)
    return self.controller.dbQuery(self, cmd, ...)
end

---
---@package
---@param msg NetMessage
function DHCP:__messageHandler(msg)
    if msg.port ~= net.standardPorts.network then
        return
    end

    local sysTime = os.epoch()

    if msg.header.type == MSG_TYPE_IP_REQUEST then
        local r = self:__dbQuery('SELECT * FROM %s WHERE owner = "%s"', LEASE_TABLE, msg.origin)
        if #r == 1 then -- If there was an entry in the lease table
            local lease = r[1] ---@type DHCP.LeaseRecord

            if lease.time == -1 or lease.time > sysTime then
                lease.time = sysTime + 9e99 + (8.64e7 * 7)
                if msg.body.hostname ~= nil then
                    -- lease.hostname = msg.body.hostname
                else
                    self:__dbQuery('UPDATE %s SET time = %s WHERE owner = "%s"', LEASE_TABLE, lease.time, msg.origin)
                end
                msg:reply(net.standardPorts.network, {
                        type = MSG_TYPE_IP_REQUEST_RETURN
                    },
                    {
                        ip = lease.ip,
                        mask = self.config.subnetMask,
                        time = lease.time,
                    }
                )
                return
            end
        end
    end
end

---@param msg RttpMessage
---@return number code
---@return string contentType
---@return string|table body
---@return RttpMessage.Header? header
function DHCP:handleRTTP(msg)
    if msg.header.path == '/dhcp' then
        local page = net.rtml.createContext(rtmlLoader.loadFile('rtml/dhcp.rtml'))
        
        local leases = self:__dbQuery('SELECT * FROM %s', LEASE_TABLE)
        ---@cast leases DHCP.LeaseRecord[]
        local y = 4
        for _, lease in pairs(leases) do
            y = y + 1
            page:addText(2, y, net.ipFormat(lease.owner))
            page:addText(18, y, os.date('%m/%d-%H:%M', lease.time / 1000)..'')
            page:addText(30, y, lease.owner)
            if lease.hostname then
                y = y + 1
                page:addText(10, y, lease.hostname)
            end
        end
        return rttp.responseCodes.okay, 'text/plain', page
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
end

function DHCP:__generateIP()
    local ip = math.random(2, 0xffffffff - self.config.subnetMask - 1)
    ip = ip + self.config.baseAddr
    while not DHCP.validAddress(ip) do
        ip = math.random(2, 0xffffffff - self.config.subnetMask - 1)
        ip = ip + self.config.baseAddr
        sleep(0)
    end
    return ip
end

return DHCP