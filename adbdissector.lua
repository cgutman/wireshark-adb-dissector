-- ADB 1.0 Protocol Dissector For Wireshark
--
-- Cameron Gutman (aicommander@gmail.com)
-- Licensed under GPLv3
--

-- Standard ADB Header
local pf_header_command = ProtoField.uint32("adb.command", "Command", base.HEX)
local pf_header_arg0 = ProtoField.uint32("adb.arg0", "Arg0", base.HEX)
local pf_header_arg1 = ProtoField.uint32("adb.arg1", "Arg1", base.HEX)
local pf_header_datalen = ProtoField.uint32("adb.datalen", "Data Length", base.HEX)
local pf_header_datachk = ProtoField.uint32("adb.datachk", "Data Checksum", base.HEX)
local pf_header_magic = ProtoField.uint32("adb.magic", "Magic", base.HEX)
local pf_header_payload = ProtoField.bytes("adb.payload", "Payload")

-- Connect message
local pf_cnxn = ProtoField.bytes("adb.cnxn", "Connect Message")
local pf_cnxn_version = ProtoField.uint32("adb.cnxn.version", "Version", base.HEX)
local pf_cnxn_maxdata = ProtoField.uint32("adb.cnxn.maxdata", "Max Data", base.HEX)
local pf_cnxn_sysident = ProtoField.string("adb.cnxn.sysident", "System Identifier")

-- Open message
local pf_open = ProtoField.bytes("adb.open", "Open Stream Message")
local pf_open_localid = ProtoField.uint32("adb.open.localid", "Local ID", base.HEX)
local pf_open_dest = ProtoField.string("adb.open.dest", "Destination")

-- Okay message
local pf_okay = ProtoField.bytes("adb.okay", "Stream Ready Message")
local pf_okay_localid = ProtoField.uint32("adb.okay.localid", "Local ID", base.HEX)
local pf_okay_remoteid = ProtoField.uint32("adb.okay.remoteid", "Remote ID", base.HEX)

-- Write message
local pf_write = ProtoField.bytes("adb.write", "Write Stream Message")
local pf_write_remoteid = ProtoField.uint32("adb.write.remoteid", "Remote ID", base.HEX)
local pf_write_data = ProtoField.bytes("adb.write.databytes", "Data (Bytes)")
local pf_write_string = ProtoField.string("adb.write.datastring", "Data (String)")

-- Close message
local pf_close = ProtoField.bytes("adb.close", "Close Stream Message")
local pf_close_localid = ProtoField.uint32("adb.close.localid", "Local ID", base.HEX)
local pf_close_remoteid = ProtoField.uint32("adb.close.remoteid", "Remote ID", base.HEX)

-- Auth messages
local pf_auth_token = ProtoField.bytes("adb.auth.token", "Auth Message (Token Signing Request)")
local pf_auth_sig = ProtoField.bytes("adb.auth.signature", "Auth Message (Signed Token Reply)")
local pf_auth_pubkey = ProtoField.bytes("adb.auth.pubkey", "Auth Message (Public Key)")
local pf_auth_payload = ProtoField.bytes("adb.auth.payload", "Auth Payload")

p_adb = Proto ("adb", "Android Debug Bridge Protocol")
p_adb.fields = {
    pf_header_command,
    pf_header_arg0,
    pf_header_arg1,
    pf_header_datalen,
    pf_header_datachk,
    pf_header_magic,
    pf_header_payload,
    pf_cnxn,
    pf_cnxn_version,
    pf_cnxn_maxdata,
    pf_cnxn_sysident,
    pf_open,
    pf_open_localid,
    pf_open_dest,
    pf_okay,
    pf_okay_localid,
    pf_okay_remoteid,
    pf_write,
    pf_write_remoteid,
    pf_write_data,
    pf_write_string,
    pf_close,
    pf_close_localid,
    pf_close_remoteid,
    pf_auth_token,
    pf_auth_sig,
    pf_auth_pubkey,
    pf_auth_payload
    }

-- Helper XOR function shamelessly scraped from the interwebs
function bxor (a,b)
  local r = 0
  for i = 0, 31 do
    local x = a / 2 + b / 2
    if x ~= math.floor (x) then
      r = r + 2^i
    end
    a = math.floor (a / 2)
    b = math.floor (b / 2)
  end
  return r
end

function p_adb.dissector(buf, pkt, root)
    pkt.cols.protocol = p_adb.name
    
    subtree = root:add(p_adb, buf(0))
    
    -- Process all the ADB packets within the TCP packet
    i = 0;
    while i < buf:len() do
        
        -- We need the full 24 byte header
        if buf:len() - i < 24 then
            -- We need another segment
            pkt.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
            pkt.desegment_offset = 0
            return
        end

        -- This marks the start of the current packet
        pktst = i
        
        command = buf(i, 4):le_uint()
        cmdentry = subtree:add(pf_header_command, buf(i, 4), command)
        i = i + 4

        arg0 = buf(i, 4):le_uint()
        arg0entry = subtree:add(pf_header_arg0, buf(i, 4), arg0)
        i = i + 4
        
        arg1 = buf(i, 4):le_uint()
        arg1entry = subtree:add(pf_header_arg1, buf(i, 4), arg1)
        i = i + 4
        
        datalen = buf(i, 4):le_uint()
        datalenentry = subtree:add(pf_header_datalen, buf(i, 4), datalen)
        i = i + 4
        
        datachk = buf(i, 4):le_uint()
        datachkentry = subtree:add(pf_header_datachk, buf(i, 4), datachk)
        i = i + 4
        
        magic = buf(i, 4):le_uint()
        magicentry = subtree:add(pf_header_magic, buf(i, 4), magic)
        i = i + 4
        
        -- Validate the magic
        if bxor(command, 0xFFFFFFFF) ~= magic then
            -- Invalid magic
            magicentry:add_expert_info(PI_MALFORMED, PI_ERROR)
            return
        end
        
        -- Make sure we've read the whole payload off the wire
        if buf:len() - i < datalen then
            -- We need another segment
            pkt.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
            pkt.desegment_offset = 0
            return
        end
        
        -- We need not have a payload
        if datalen ~= 0 then
            payloadentry = subtree:add(pf_header_payload, buf(i, datalen))
        
            -- Validate the payload checksum
            dataend = i + datalen
            ourchksum = 0;
            while i < dataend do
                ourchksum = ourchksum + buf(i, 1):uint()
                i = i + 1
            end
        
            if ourchksum ~= datachk then
                -- Invalid payload checksum
                datachkentry:add_expert_info(PI_CHECKSUM, PI_WARN)
            end
        end
        
        -- Process the specific commands
        subtree:add("")
        if command == 0x4e584e43 then
            -- CNXN
            subtree:add(pf_cnxn, buf(pktst, datalen+24))
            
            versionentry = subtree:add(pf_cnxn_version, buf(pktst+4, 4), arg0)
            if arg0 ~= 0x01000000 then
                -- Invalid version
                versionentry:add_expert_info(PI_PROTOCOL, PI_WARN)
            end
            
            maxdataentry = subtree:add(pf_cnxn_maxdata, buf(pktst+8, 4), arg1)
            if arg1 == 0 then
                -- Invalid max data
                maxdataentry:add_expert_info(PI_PROTOCOL, PI_WARN)
            end
            
            if datalen == 0 then
                -- No sysident string
                datalenentry:add_expert_info(PI_MALFORMED, PI_ERROR)
                return
            end
            
            sysident = buf(pktst+24, datalen):string()
            sysidententry = subtree:add(pf_cnxn_sysident, buf(pktst+24, datalen), sysident)
        elseif command == 0x4e45504f then
            -- OPEN
            subtree:add(pf_open, buf(pktst, datalen+24))
            
            localidentry = subtree:add(pf_open_localid, buf(pktst+4, 4), arg0)
            if arg0 == 0 then
                -- Invalid local ID
                localidentry:add_expert_info(PI_PROTOCOL, PI_WARN)
            end
            
            if arg1 ~= 0 then
                -- Remote ID must be zero
                arg0entry:add_expert_info(PI_PROTOCOL, PI_WARN)
            end
            
            if datalen == 0 then
                -- We must have a destination to open
                datalenentry:add_expert_info(PI_PROTOCOL, PI_ERROR)
                return
            end
            
            dest = buf(pktst+24, datalen):string()
            destentry = subtree:add(pf_open_dest, buf(pktst+24, datalen), dest)
        elseif command == 0x59414b4f then
            -- OKAY
            subtree:add(pf_okay, buf(pktst, datalen+24))
            
            localidentry = subtree:add(pf_okay_localid, buf(pktst+4, 4), arg0)
            if arg0 == 0 then
                -- Invalid local ID
                localidentry:add_expert_info(PI_PROTOCOL, PI_WARN)
            end
            
            remoteidentry = subtree:add(pf_okay_remoteid, buf(pktst+8, 4), arg1)
            if arg1 == 0 then
                -- Invalid remote ID
                remoteidentry:add_expert_info(PI_PROTOCOL, PI_WARN)
            end
            
            if datalen ~= 0 then
                -- We shouldn't have a payload here
                datalenentry:add_expert_info(PI_PROTOCOL, PI_WARN)
            end
        elseif command == 0x45534c43 then
            -- CLOSE
            subtree:add(pf_close, buf(pktst, datalen+24))
            
            localidentry = subtree:add(pf_close_localid, buf(pktst+4, 4), arg0)
            
            remoteidentry = subtree:add(pf_close_remoteid, buf(pktst+8, 4), arg1)
            if arg1 == 0 then
                -- Invalid remote ID
                remoteidentry:add_expert_info(PI_PROTOCOL, PI_WARN)
            end
            
            if datalen ~= 0 then
                -- We shouldn't have a payload here
                datalenentry:add_expert_info(PI_PROTOCOL, PI_WARN)
            end
        elseif command == 0x45545257 then
            -- WRITE
            subtree:add(pf_write, buf(pktst, datalen+24))
            
            remoteidentry = subtree:add(pf_write_remoteid, buf(pktst+8, 4), arg1)
            if arg1 == 0 then
                -- Invalid remote ID
                remoteidentry:add_expert_info(PI_PROTOCOL, PI_WARN)
            end
            
            if datalen == 0 then
                -- We should have a payload here
                datalenentry:add_expert_info(PI_PROTOCOL, PI_ERROR)
                return
            end
            
            dataentry = subtree:add(pf_write_data, buf(pktst+24, datalen))
            
            datastring = buf(pktst+24, datalen):string()
            stringentry = subtree:add(pf_write_string, buf(pktst+24, datalen), datastring)

        elseif command == 0x48545541 then
            -- AUTH
            if arg0 == 1 then
                -- Token request
                subtree:add(pf_auth_token, buf(pktst, datalen+24))
            elseif arg0 == 2 then
                -- Signature reply
                subtree:add(pf_auth_sig, buf(pktst, datalen+24))
                
                if datalen ~= 0x100 then
                    -- Signature length is wrong
                    datalenentry:add_expert_info(PI_PROTOCOL, PI_WARN)
                    return
                end
            elseif arg0 == 3 then
                -- Public key
                subtree:add(pf_auth_pubkey, buf(pktst, datalen+24))
            else
                -- Unrecognized type
                arg0entry:add_expert_info(PI_PROTOCOL, PI_ERROR)
                return
            end
            
            authpayload = subtree:add(pf_auth_payload, buf(pktst+24, datalen))
        else
            -- Unrecognized message
            cmdentry:add_expert_info(PI_PROTOCOL, PI_ERROR)
            return
        end
    end
end

function p_adb.init()
end

-- Devices listen on TCP port 5555 for remote ADB connections
local tcp_dissector_table = DissectorTable.get("tcp.port")
tcp_dissector_table:add(5555, p_adb)