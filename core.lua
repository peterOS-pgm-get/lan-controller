pos.require("net.rttp")
pos.require('net.rtml')
local rtmlLoader = pos.require('net.rtml.rtmlLoader')
local sha256 = pos.require("hash.sha256")

print('Starting LAN-Controller')

---@class LANControllerConfig
local defaultConfig = {
    database = 'lan-controller',

    baseAddr = '192.168.0.0', ---@type string|number
    subnetMask = '255.255.0.0', ---@type string|number

    modems = {
        outside = 'top',
        inside = 'back'
    },

    remoteControl = {
        enabled = false,
        password = 'admin'
    },
    
    assignLANHostname = false,

    hostname = nil,
    global = false,
    verbose = false,
}
local config = pos.Config('%appdata%/lan-controller/config.json', defaultConfig, true)
local cfg = config.data ---@type LANControllerConfig

cfg.baseAddr = net.ipToNumber(cfg.baseAddr)
cfg.subnetMask = net.ipToNumber(cfg.subnetMask)

local logger = pos.Logger('lan-controller.log', false, true)

---@class LANController
---@field insideInterface NetInterface
---@field outsideInterface NetInterface
---@field config LANControllerConfig
---@field dhcp DHCP
---@field dns DNS
---@field nat NAT
local LANController = {
    config = cfg
}

---@class LANController.Service
---@field controller LANController
---@field logger Logger
---@field start fun(self: LANController.Service, controller: LANController): nil
---@field handleRTTP fun(self: LANController.Service, msg: RttpMessage): code: number, contentType: string, body: table|string, header: RttpMessage.Header

if not netdb then
    logger:error('Could not start: NetDB non available')
    error('NetDB must be started before LAN-Controller')
end

if not netdb.server.hasDb(LANController.config.database) then
    netdb.server.createDatabase(LANController.config.database)
end

---@param service LANController.Service
---@param cmd string
---@vararg string|number
---@return any
function LANController.dbQuery(service, cmd, ...)
    if ... then
        cmd = cmd:format(...)
    end
    logger:debug('Running DB query: `%s`', cmd)
    service.logger:debug('Running DB query: `%s`', cmd)
    local s, r = netdb.server.run(LANController.config.database, cmd)
    if not s then
        service.logger:error('DB Error: %s', r)
        error('DB Error: ' .. r, 2)
    end
    return r
end

local insideInterface = net.NetInterface('lan_0', cfg.modems.inside, cfg.baseAddr + 1)
---@diagnostic disable-next-line: invisible
insideInterface.__subnetMask = cfg.subnetMask --[[@as number]]
insideInterface:setConfig({ respondToPing = true, receiveAll = (not cfg.global), verbose = cfg.verbose })
insideInterface:setup()
insideInterface:open(net.standardPorts.rttp)
LANController.insideInterface = insideInterface
local outsideInterface = insideInterface;
if not cfg.global then
    outsideInterface = net.NetInterface('ext_0', cfg.modems.outside)
    outsideInterface:setConfig({ respondToPing = true, hostname = cfg.hostname, verbose = cfg.verbose })
    outsideInterface:setup()
    net.setDefaultInterface(outsideInterface)
else
    net.setDefaultInterface(insideInterface)
end
LANController.outsideInterface = outsideInterface

local dhcp = dofile('dhcp.lua') --[[@as DHCP]].new(LANController, pos.Logger('dhcp.log', false, true)) ---@type DHCP
LANController.dhcp = dhcp
local dns = dofile('dns.lua')--[[@as DNS]].new(LANController, pos.Logger('dns.log', false, true)) ---@type DNS
LANController.dns = dns
local nat = dofile('nat.lua')--[[@as NAT]].new(LANController, pos.Logger('nat.log', false, true)) ---@type NAT
LANController.nat = nat

dhcp:start()
dns:start()
if not cfg.global then
    nat:start()
else
    print("Starting global controller")
end

local tokens = {} ---@type { [string]: LANController.Token }
---@class LANController.Token
---@field token string
---@field expire number

---@param msg RttpMessage
local function processRTTP(msg, token)
    local origin = net.getOriginString(msg)
    if msg.header.path == '/' then
        if msg.header.method == 'POST' then
            if msg.body.vals.user ~= 'admin' then
                return rttp.responseCodes.unauthorized, 'text/plain', 'invalid credentials'
            end
            if msg.body.vals.pass ~= cfg.remoteControl.password then
                return rttp.responseCodes.unauthorized, 'text/plain', 'invalid credentials'
            end
            token = sha256.hash(origin .. string.randomString(8))
            tokens[origin] = {
                expire = os.epoch('utc') + (10 * 60 * 1000),
                token = token
            }
            local dest = '/panel'
            if msg.header.cookies and msg.header.cookies.redirect and msg.header.cookies.redirect ~= '' then
                dest = msg.header.cookies.redirect
            end
            return rttp.responseCodes.movedTemporarily, 'text/plain', 'valid login', { redirect = dest, cookies = { token = token, redirect = '' } }
        end
        if token then
            local dest = '/panel'
            if msg.header.cookies and msg.header.cookies.redirect and msg.header.cookies.redirect ~= '' then
                dest = msg.header.cookies.redirect
            end
            return rttp.responseCodes.movedTemporarily, 'text/plain', 'already logged in', { redirect = dest, cookies = { redirect = '' } }
        end
        
        return rttp.responseCodes.okay, 'table/rtml', rtmlLoader.loadFile('/os/bin/lan-controller/rtml/login.rtml')
    elseif msg.header.path == '/logout' then
        tokens[origin] = nil
        return rttp.responseCodes.movedTemporarily, 'text/plain', 'logged out', { cookies = { token = '' }, redirect = '/' }
    elseif msg.header.path == '/panel' then
        return rttp.responseCodes.okay, 'table/rtml', rtmlLoader.loadFile('/os/bin/lan-controller/rtml/panel.rtml')
    else
        return rttp.responseCodes.notFound, 'table/rtml', rtmlLoader.loadFile('/os/bin/lan-controller/rtml/404.rtml')
    end
end

insideInterface:addMsgHandler(function(msg)
    if msg.header.type == 'rttp' then
        if not cfg.remoteControl.enabled then
            msg:reply(msg.port, {
                type = 'rttp',
                code = rttp.responseCodes.serviceUnavailable,
                contentType = 'text/plain'
            }, 'Remote control not enabled on this LAN-Controller')
            return
        end

        ---@cast msg RttpMessage
        local code, contentType, body, header = rttp.responseCodes.internalServerError, 'text/plain', 'Unknown Internal Error', nil ---@type number, string, any, RttpMessage.Header?

        local origin = net.getOriginString(msg)

        local sysTime = os.epoch('utc')
        local token = nil
        if not (msg.header.cookies and msg.header.cookies.token) then
            if msg.header.path ~= '/' then
                token = nil
            end
        elseif msg.header.path ~= '/' then
            token = tokens[origin]
            if not token then
                token = nil
            elseif token.token ~= msg.header.cookies.token then
                token = nil
            elseif token.expire < sysTime then
                token = nil
                tokens[origin] = nil
            else
                token.expire = sysTime + (10 * 60 * 1000)
            end
        end

        if token and msg.header.path == '/' then
            code = rttp.responseCodes.movedTemporarily
            header = {
                type = 'rttp',
                redirect = '/panel',
                cookies = { redirect = '' }
            }
            contentType = 'text/plain'
            body = 'Already logged in'
        elseif token then
            local s, e = pcall(function()
                if msg.header.path:start('/dhcp') then
                    code, contentType, body, header = dhcp:handleRTTP(msg)
                elseif msg.header.path:start('/nat') then
                    if cfg.global then
                        code = rttp.responseCodes.serviceUnavailable
                        contentType= 'table/rtml'
                        body = rtmlLoader.loadFile('/os/bin/lan-controller/rtml/serviceInactive.rtml')
                    else
                        code, contentType, body, header = nat:handleRTTP(msg)
                    end
                elseif msg.header.path:start('/dns') then
                    code, contentType, body, header = dns:handleRTTP(msg)
                else
                    code, contentType, body, header = processRTTP(msg, token)
                end
            end)
            if not s then
                logger:error('RTTP Handler Error: %s', e)
            end
        elseif msg.header.path == '/' then
            local s, e = pcall(function()
                code, contentType, body, header = processRTTP(msg, token)
            end)
            if not s then
                logger:error('RTTP Handler Error: %s', e)
            end
        else
            code = rttp.responseCodes.movedTemporarily
            header = {
                type = 'rttp',
                redirect = '/',
                cookies = { token = '', redirect = msg.header.path }
            }
            contentType = 'text/plain'
            body = 'Must log in first'
        end

        if not header then
            header = { type = 'rttp' }
        end
        header.type = 'rttp'
        header.code = code
        header.contentType = contentType

        msg:reply(msg.port, header, body)
    end
end)