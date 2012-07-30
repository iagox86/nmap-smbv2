---
-- This implements the NTLM protocol as defined in [MS-NLMP]. This includes
-- lanman, lanman v2, ntlm, and ntlmv2. 
--

local bin = require "bin"
local nmap = require "nmap"
local openssl = require "openssl"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local nsedebug = require "nsedebug"
local test = require "test"

_ENV = stdnse.module("ntlm", stdnse.seeall)

have_ssl = (nmap.have_ssl() and pcall(require, "openssl"))

-- MessageTypes, defined in [MS-NLMP] 2.2
local NtLmNegotiate    = 0x00000001
local NtLmChallenge    = 0x00000002
local NtLmAuthenticate = 0x00000003

local HASH_TYPE_LANMAN   = 0x00
local HASH_TYPE_NTLM     = 0x01
local HASH_TYPE_LANMANv2 = 0x03
local HASH_TYPE_NTLMv2   = 0x04

-- Negotiate flags, defined in [MS-NLMP] 2.2.2.5
local NTLMSSP_NEGOTIATE_56                         = 0x80000000 -- 'W'
-- Should be used for improved security. See [MS-NLMP] 3.2.5.1.2, 3.2.5.2.1, 3.2.5.2.2
local NTLMSSP_NEGOTIATE_KEY_EXCH                   = 0x40000000 -- 'V'
local NTLMSSP_NEGOTIATE_128                        = 0x20000000 -- 'U'
local NTLMSSP_RESERVED_1                           = 0x10000000 -- 'r1'
local NTLMSSP_RESERVED_2                           = 0x08000000 -- 'r2'
local NTLMSSP_RESERVED_3                           = 0x04000000 -- 'r3'
-- Requests the protocol version number
local NTLMSSP_NEGOTIATE_VERSION                    = 0x02000000 -- 'T'
local NTLMSSP_RESERVED_4                           = 0x01000000 -- 'r3'
-- Populates the TargetInfo fields. See [MS-NLMP] 2.2.1.2
local NTLMSSP_NEGOTIATE_TARGET_INFO                = 0x00800000 -- 'S'
-- Requests LMOWF() [MS-NLMP] 3.3
local NTLMSSP_NEGOTIATE_NON_NT_SESSION_KEY         = 0x00400000 -- 'R'
local NTLMSSP_RESERVED_5                           = 0x00200000 -- 'r5'
-- Requests an identity-level token
local NTLMSSP_NEGOTIATE_IDENTIFY                   = 0x00100000 -- 'Q'
-- Requests v2 session security (not NTLMv2)
local NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY  = 0x00080000 -- 'P'
local NTLMSSP_RESERVED_6                           = 0x00040000 -- 'r6'
-- TargetName must be a server name
local NTLMSSP_TARGET_TYPE_SERVER                   = 0x00020000 -- 'O'
-- TargetName must be a domain name
local NTLMSSP_TARGET_TYPE_DOMAIN                   = 0x00010000 -- 'N'
-- Request a signature block on all messages
local NTLMSSP_NEGOTIATE_ALWAYS_SIGN                = 0x00008000 -- 'M'
local NTLMSSP_RESERVED_7                           = 0x00004000 -- 'r7'
local NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED   = 0x00002000 -- 'L'
-- If set, domain name is provided. See [MS-NLMP] 2.2.1.1
local NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED        = 0x00001000 -- 'K'
local NTLMSSP_NEGOTIATE_ANONYMOUS                  = 0x00000800 -- 'J'
local NTLMSSP_RESERVED_8                           = 0x00000400 -- 'r8'
-- Requests the use of NTLMv1
local NTLMSSP_NEGOTIATE_NTLM                       = 0x00000200 -- 'H'
local NTLMSSP_RESERVED_9                           = 0x00000100 -- 'r9'
-- Requests Lanman session key computation
local NTLMSSP_NEGOTIATE_LM_KEY                     = 0x00000080 -- 'G'
local NTLMSSP_NEGOTIATE_DATAGRAM                   = 0x00000040 -- 'F'
local NTLMSSP_NEGOTIATE_SEAL                       = 0x00000020 -- 'E'
local NTLMSSP_NEGOTIATE_SIGN                       = 0x00000010 -- 'D'
local NTLMSSP_RESERVED_10                          = 0x00000008 -- 'r10'
-- Set the TargetName field of the client ([MS-NLMP] 2.2.1.2)
local NTLMSSP_REQUEST_TARGET                       = 0x00000004 -- 'C'
-- Use non-unicode
local NTLMSSP_NEGOTIATE_OEM                        = 0x00000002 -- 'B'
-- Use unicode
local NTLMSSP_NEGOTIATE_UNICODE                    = 0x00000001 -- 'A'

Ntlm =
{
  new = function(self, username, password)
    local o = { }
    setmetatable(o, self)
    self.__index = self

    o.password = password
    o.flags = bit.bor(NTLMSSP_NEGOTIATE_ALWAYS_SIGN, NTLMSSP_NEGOTIATE_NTLM, NTLMSSP_NEGOTIATE_SIGN, NTLMSSP_NEGOTIATE_UNICODE)
    o.seq = 1
    o.random_session_key = openssl.rand_bytes(16)
    o.workstation = ''
    o.server = ''
    o.time = (0 + 11644473600) * 10000000
    o.server_challenge = ("\0"):rep(8)
    o.client_challenge = ("\0"):rep(8)
    o.enable_lm = true
    self:set_version(0x05, 0x01, 2600, 0, 0x0f)

    if(username:match('\\')) then
      local parts = stdnse.strsplit('\\', username)
      o.domain   = parts[1]
      o.username = parts[2]

    elseif(username:match('@')) then
      local parts = stdnse.strsplit('@', username)
      o.username = parts[1]
      o.domain   = parts[2]

    else
      o.domain = ''
      o.username = username
    end

    return o
  end,

  ---Not a good idea to use this in production.
  set_random_session_key = function(self, session_key)
    self.random_session_key = session_key
  end,

  set_server = function(self, server)
    self.server = server
  end,

  set_workstation = function(self, workstation)
    self.workstation = workstation
  end,

  set_time = function(self, time)
    self.time = time
  end,

  set_client_challenge = function(self, client_challenge)
    self.client_challenge = client_challenge
  end,

  set_server_challenge = function(self, server_challenge)
    self.server_challenge = server_challenge
  end,

  set_flags = function(self, flags)
    self.flags = flags
  end,

  -- The NTLM_NEGOTIATE message is defined in [MS-NLMP] 2.2.1.1
  get_ntlm_negotiate = function(self)

    return bin.pack("<AIIIIA",
      "NTLMSSP\0",   -- Signature
      NtLmNegotiate, -- MessageType
      self.flags,    -- Flags
      0,             -- Workstation domain
      0,             -- Workstation name
      ''             -- Payload
    )
  end,

  -- The NTLM_CHALLENGE message is defined in [MS-NLMP] 2.2.1.2
  parse_ntlm_challenge = function(self, message)
    local pos, signature, messagetype, targetnamelen, targetnamemaxlen, targetnamebufferoffset, flags, serverchallenge, reseved, targetinfolen, targetinfomaxlen, targetinfobufferoffset, version = bin.unpack("<A8ISSIIA8A8SSILA", message)

    -- Do some basic verifications
    if(not(version)) then
      return false, "Could not parse NTLM_CHALLENGE response"
    end
    payload = ''
    if(pos ~= 0) then
      payload = message:sub(pos - 1)
    end
    if(signature ~= "NTLMSSP\0") then
      return false, "Bad server signature: " .. signature
    end

    -- Update the flags based on the server's flags
    self.flags = bit.band(self.flags, flags)

    -- [MS-NLMP] 3.1.5.2.1
    -- When the client receives a CHALLENGE_MESSAGE, it MUST produce a challenge response and an encrypted session key. The client MUST send the negotiated features (flags), the user name, the user's domain, the client part of the challenge, the challenge response, and the encrypted session key to the server. This message is sent to the server as an AUTHENTICATE_MESSAGE.
    return true
  end,

  -- NTLMSSP_MESSAGE_SIGNATURE defined in [MS-NLMP] 2.2.2.9.1, 3.4.4
  -- Used when NTLMSSP_NEGOTIATE_EXTENDED_SECURITY is not set
  getNtlmsspMessageSignature = function()
    -- [4 bytes] Version - must be 1
    -- [4 bytes] RandomPad
    -- [4 bytes] Checksum
    -- [4 bytes] SeqNum
  end,

  -- NTLMSSP_MESSAGE_SIGNATURE for Extended Session Security, defined in [MS-NLMP] 2.2.2.9.2, 3.4.4
  getNtlmsspMessageSignatureEss = function()
    -- [4 bytes] Version - must be 1
    -- [8 bytes] Checksum
    -- [4 bytes] SeqNum
  end,

  -- [1 byte] Product major version - 0x05 or 0x06
  -- [1 byte] Product minor version - 0x00, 0x01, or 0x02
  -- [2 bytes] ProductBuild
  -- [3 bytes] Reserved - 0
  -- [1 bytes] NTLMRevisionCurrent - 0x0f = win2k3, nothing else defined
  set_version = function(self, major, minor, build, reserved, current_revision)
    self.version = self.version or {}

    self.version.major            = major            or self.version.major
    self.version.minor            = minor            or self.version.minor
    self.version.build            = build            or self.version.build
    self.version.reserved         = reserved         or self.version.reserved
    self.version.current_revision = current_revision or self.version.current_revision
  end,

  -- The version structure, if NTLMSSP_NEGOTIATE_VERSION is on. [MS-NLMP] 2.2.2.10
  get_version = function(self)
    -- Set up the last field which is the 3-byte reserved value followed by
    -- the one-byte current revision value
    local last_field = 0
    last_field = bit.bor(last_field, bit.lshift(bit.band(self.version.current_revision, 0x000000FF), 24))
    last_field = bit.bor(last_field, bit.lshift(bit.band(self.version.reserved,         0x00FFFFFF), 0))

    return bin.pack("<CCSI",
      self.version.major,
      self.version.minor,
      self.version.build,
      last_field
    )
  end,

  -- The NTLM_AUTHENTICATE message is defined in [MS-NLMP] 2.2.1.3
  get_ntlm_authenticate = function(self)
    -- Convert the username and domain to unicode
    local domain   = self:encode_string(self.domain)
    local username = self:encode_string(self.username)

    local status, lanman, ntlm = self:ComputeResponse()
    if(not(status)) then
      return status, lanman
    end

    -- [MS-NLMP] 3.1.5.1.2 and (3.2.5?) [TODO]
    local session_key
    local status, KXKEY = self:KXKEY()
    if(not(status)) then
      return status, KXKEY
    end

    if(bit.band(self.flags, NTLMSSP_NEGOTIATE_KEY_EXCH) == 0) then
      session_key = ''
    else
      session_key = openssl.encrypt("RC4", KXKEY, nil, self.random_session_key)
    end

    workstation = self:encode_string(self.workstation)

    version = ''
    if(bit.band(self.flags, NTLMSSP_NEGOTIATE_VERSION)) then
      version = self:get_version()
    end

    signature = '' -- TODO

    -- This is where the 'payload' starts
    len = 0x40 + #version + #signature

    new_blob = bin.pack("<AISSISSISSISSISSISSIIAA",
      "NTLMSSP\0",                                                -- Signature
      NtLmAuthenticate,                                           -- MessageType

      #lanman,                                                    -- LmChallengeResponseLen (0 if not using LM)
      #lanman,                                                    -- LmChallengeResponseMaxLen
      len + #domain + #username + #workstation,                   -- LmChallengeResponseOffset

      #ntlm,                                                      -- NtChallengeResponseLen (0 if not using NT)
      #ntlm,                                                      -- NtChallengeResponseMaxLen
      len + #domain + #username + #workstation + #lanman,         -- NtChallengeResponseOffset

      #domain,                                                    -- DomainNameLen
      #domain,                                                    -- DomainNameMaxLen
      len,                                                        -- DomainNameOffset

      #username,                                                  -- UserNameLen
      #username,                                                  -- UserNameMaxLen
      len + #domain,                                              -- UserNameOffset

      #workstation,                                               -- WorkstationLength
      #workstation,                                               -- WorkstationMaxLength
      len + #domain + #username,                                  -- WorkstationOffset

      #session_key,                                               -- EncryptedRandomSessionKeyBufferLen
      #session_key,                                               -- EncryptedRandomSessionKeyBufferMaxLen
      len + #domain + #username + #workstation + #lanman + #ntlm, -- EncryptedRandomSessionKeyBufferOffset

      self.flags,                                                 -- NegotiateFlags
      version,                                                    -- Version
      signature                                                   -- Signature
    )

    --new_blob = new_blob .. bin.pack("AAAAAA", lanman, ntlm, domain, username, workstation, session_key)
    new_blob = new_blob .. bin.pack("AAAAAA", domain, username, workstation, lanman, ntlm, session_key)

    return true, new_blob
  end,

  to_unicode = function(str)
    local unicode = ""

    for i = 1, #str, 1 do
      unicode = unicode .. bin.pack("<S", string.byte(str, i))
    end

    return unicode
  end,

  encode_string = function(self, str)
    if(bit.band(self.flags, NTLMSSP_NEGOTIATE_UNICODE) ~= 0) then
      return self.to_unicode(str)
    else
      return str
    end
  end,

  ---Generate the LMv1 hash. See [MS-NLMP] 3.3.1.
  --
  --@return (status, hash) If status is true, the hash is returned; otherwise, an error message is returned.
  LMOWFv1 = function(self)
    if(have_ssl ~= true) then
      return false, "NTLM: OpenSSL not present"
    end

    local str1, str2
    local key1, key2
    local result

    -- Convert the password to uppercase
    password = string.upper(self.password)

    -- If password is under 14 characters, pad it to 14
    if(#password < 14) then
      password = password .. string.rep(string.char(0), 14 - #password)
    end

    -- Take the first and second half of the password (note that if it's longer than 14 characters, it's truncated)
    str1 = string.sub(password, 1, 7)
    str2 = string.sub(password, 8, 14)

    -- Generate the keys
    key1 = openssl.DES_string_to_key(str1)
    key2 = openssl.DES_string_to_key(str2)

    -- Encrypt the string "KGS!@#$%" with each half, and concatenate it
    result = openssl.encrypt("DES", key1, nil, "KGS!@#$%") .. openssl.encrypt("DES", key2, nil, "KGS!@#$%")

    return true, result
  end,

  ---Generate the NTLMv1 hash. See [MS-NLMP] 3.3.1
  --
  --@return (status, hash) If status is true, the hash is returned; otherwise, an error message is returned.
  NTOWFv1 = function(self)
    if(have_ssl ~= true) then
      return false, "NTLM: OpenSSL not present"
    end

    return true, openssl.md4(self.to_unicode(self.password))
  end,

  -- [MS-NLMP] 3.3.1
  ResponseKeyNT = function(self)
    return self:NTOWFv1()
  end,

  -- [MS-NLMP] 3.3.1
  ResponseKeyLM = function(self)
    return self:LMOWFv1()
  end,

  ---See [MS-NLMP] 6.0
  -- DES Long-form
  DESL = function(key, data)
    if(have_ssl ~= true) then
      return false, "NTLM: OpenSSL not present"
    end

    local key1, key2, key3
    local result

    -- Pad the key to 21 characters
    key = key .. string.rep("\0", 21 - #key)

    -- Take the first and second half of the password (note that if it's longer than 14 characters, it's truncated)
    key1 = string.sub(key, 1,  7)
    key2 = string.sub(key, 8,  14)
    key3 = string.sub(key, 15, 21)

    -- Generate the keys
    key1 = openssl.DES_string_to_key(key1)
    key2 = openssl.DES_string_to_key(key2)
    key3 = openssl.DES_string_to_key(key3)

    -- Encrypt the challenge with each key
    result = openssl.encrypt("DES", key1, nil, data) .. openssl.encrypt("DES", key2, nil, data) .. openssl.encrypt("DES", key3, nil, data)

    return true, result
  end,

  ComputeResponse = function(self)
    if(have_ssl ~= true) then
      return false, "NTLM: OpenSSL not present"
    end

  -- Special case for anonymous authentiation
  -- TODO: Handle this
--  if(self.username == '' and self.password == '') then
--    NtChallengeResponseLen = 0
--    NtChallengeResponseMaxLen = 0
--    NtChallengeresponseBufferOffset = 0
--    LmChallengeResponse = "\0"
--  end

---[MS-NLMP] 3.3.1
    if(bit.band(self.flags, NTLMSSP_NEGOTIATE_NTLM)) then
      -- LM_RESPONSE, defined in [MS-NLMP] 2.2.2.3
      -- [24 bytes] LmChallengeResponse [MS-NLMP] 3.3.1
      local status, ResponseKeyLM = self:LMOWFv1()
      if(not(status)) then
        return false, ResponseKeyLM
      end

      -- NTLM_RESPONSE, defined in [MS-NLMP] 2.2.2.6
      -- [24 bytes] NtChallengeResponse
      local status, ResponseKeyNT = self:NTOWFv1()
      if(not(status)) then
        return false, ResponseKeyNT
      end

      if(bit.band(self.flags, NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY) ~= 0) then
        status, NtChallengeResponse = Ntlm.DESL(ResponseKeyNT, string.sub(openssl.md5(ServerChallenge .. ClientChallenge), 1, 7))
        LmChallengeResponse = ClientChallenge .. string.rep("\x00", 16)
      else
        status, NtChallengeResponse = Ntlm.DESL(ResponseKeyNT, self.server_challenge)
        if(self.enable_lm) then
          status, LmChallengeResponse = Ntlm.DESL(ResponseKeyLM, self.server_challenge)
        else
          LmChallengeResponse = NtChallengeResponse
        end
      end

      return true, LmChallengeResponse, NtChallengeResponse
    else
      -- LMv2_RESPONSE, defined in [MS-NLMP] 2.2.2.4
      -- [16 bytes] LmChallengeResponse [MS-NLMP] 3.3.2 [TODO]
      -- [8 bytes]  ClientChallenge [MS-NLM{] 3.1.5.1.2 [TODO]
      --
      -- NTLMv2_CLIENT_CHALLENGE, defined in [MS-NLMP] 2.2.2.7
      -- [1 byte] RespType - Current version (1)
      -- [1 byte] HiRespType - Maximum version (1)
      -- [2 bytes] Reserved1 - 0
      -- [4 bytes] Reserved2 - 0
      -- [8 bytes] Timestamp - 100ns ticks since 1900
      -- [8 bytes] ChallengeFromClient - Client challenge ([MS-NLMP] 3.1.5.1.2)
      -- [4 bytes] Reserved3 - 0
      -- [variable] AvPairs - A series of AV-PAIR structures ([MS-NLMP] 2.2.2.1), terminated by MsvAvEOL
--    temp = Responserversion .. HiResponserversion .. Z(6) .. Time .. ClientChallenge .. Z(4) .. ServerName .. Z(4)
--    NTProofStr = openssl.hmac("MD5", ResponseKeyNT, CHALLENGE_MESSAGE.ServerChallenge .. temp)
--    NtChallengeResponse = NTProofStr .. temp
--    LmChallengeResponse = oenssl.hmac("MD5", ResponseKeyLM, CHALLENGE_MESSAGE.ServerChallenge .. ClientChallenge) .. ClientChallenge
    end
  end,

  SessionBaseKey = function(self)
    -- TODO: Check for OpenSSL
    if(have_ssl ~= true) then
      return false, "SMB: OpenSSL not present"
    end

    if(bit.band(self.flags, NTLMSSP_NEGOTIATE_NTLM) ~= 0) then
      -- Defined in [MS-NLMP] 3.3.1
      local status, result = self:NTOWFv1()
      if(not(result)) then
        return false, result
      end
      return true, openssl.md4(result)
    else
--      SessionBaseKey = openssl.hmac("MD5", ResponseKeyNT, NTProofStr)
    end
  end,

  -- [MS-NLMP] 3.3.2
  NTOWFv2 = function(self)
    if(have_ssl ~= true) then
      return false, "SMB: OpenSSL not present"
    end

    return true, openssl.hmac("MD5", openssl.md4(self.to_unicode(self.password)), string.upper(self.username .. self.domain))
  end,

  -- [MS-NLMP] 3.3.2
  LMOWFv2 = function(self)
    return self:NTOWFv2()
  end,

  ResponseKeyNT = function(self)
    return self:NTOWFv2()
  end,

  ResponseKeyLM = function(self)
    return self:LMWFv2()
  end,

--
---- [MS-NLMP] 3.4.2
--function SIGN(Handle, SigningKey, Seqnum, Message)
--  return message + MAC(Handle, SigningKey, SeqNum, Message)
--end
--
---- [MS-NLMP] 3.4.3
--function SEAL(Handle, SigningKey, Seqnum, Message)
--  SealedMessage = RC4(Handle, Message)
--  Signature = MAC(Handle, SigningKey, SeqNum, Message)
--end

--  MAC = function(self, Handle, SigningKey, SeqNum, Message)
--    if(bit.band(flags, NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY) ~= 0) then
--      -- [MS-NLMP] 3.4.4.2 (with ESS)
--      if(bit.bor(self.flags, NTLMSSP_NEGOTIATE_KEY_EXCH)) then
--        Version = 0x0000001
--        Checksum = RC4(Handle, string.sub(openssl.hmac("MD5", SigningKey, self.seq .. Message), 1, 7))
--        self.seq = self.seq + 1
--      else
--        Version = 0x0000001
--        Checksum = string.sub(openssl.hmac("MD5", SigningKey, self.seq .. Message), 1, 7)
--        self.seq = self.seq
--        self.seq = self.seq + 1
--      end
--    else
--      -- [MS-NLMP] 3.4.4.1 (with ESS)
--      Version = 0x0000001
--      Checksum = CRC32(Message)
--      RandomPad = RC4(Handle, 0x00000000)
--      Checksum = RC4(Handle, Checksum)
--      ThisSeqNum = RC4(Handle, 0x00000000)
--      ThisSeqNum = bit.bxor(ThisSeqNum, self.seq)
--      self.seq = self.seq + 1 -- TODO: Make this actually change
--    end
--  end,

--
---- [MS-NLMP] 3.4.5.1
  KXKEY = function(self)
    local result, session_base_key = self:SessionBaseKey()
    local result, LmChallengeResponse, NtChallengeResponse = self:ComputeResponse()
    local result, LMOWF = self:LMOWFv1()

    if(bit.band(self.flags, NTLMSSP_NEGOTIATE_NTLM) ~= 0 and bit.band(self.flags, NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY) ~= 0) then
      -- TODO
      --return true, openssl.hmac("MD5", session_base_key, self.server_challenge .. string.sub(LmChallengeResponse, 1, 7))
    elseif(bit.band(self.flags, NTLMSSP_NEGOTIATE_NTLM) ~= 0) then
      if(bit.band(self.flags, NTLMSSP_NEGOTIATE_LM_KEY) ~= 0) then
        local key1 = string.sub(LMOWF, 1, 7)
        local key2 = string.sub(LMOWF, 8, 8) .. "\xBD\xBD\xBD\xBD\xBD\xBD"
        key1 = openssl.DES_string_to_key(key1)
        key2 = openssl.DES_string_to_key(key2)

        local data = string.sub(LmChallengeResponse, 1, 8)
        return true, openssl.encrypt("DES", key1, nil, data) .. openssl.encrypt("DES", key2, nil, data)
      else
        if(bit.band(self.flags, NTLMSSP_NEGOTIATE_NON_NT_SESSION_KEY) ~= 0) then
          local key1 = string.sub(LMOWF, 1, 8)
          local key2 = ("\0"):rep(8)
          return true, key1 .. key2
        else
          return true, session_base_key
        end
      end
    else
      return false, "KXKEY can't be generated with the current flags: 0x" .. string.format("%08x", self.flags)
    end
  end,
--
---- [MS-NLMP] 3.4.5.2
--function SIGNKEY(RandomSessionKey, mode)
--  if(bit.band(flags, NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY)) then
--    if(mode == "Client") then
--      return openssl.md5(RandomSessionKey .. "session key to client-to-server signing key magic constant")
--    else
--      return openssl.md5(RandomSessionKey .. "session key to server-to-client signing key magic constant")
--    end
--  else
--    -- No key without ESS
--    return nil
--  end
--end

-- [MS-NLMP] 3.4.5.3
--  SEALKEY = function(self, mode)
--    if(bit.band(self.flags, NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY) ~= 0) then
-- TODO
--    if(bit.band(flags, NTLMSSP_NEGOTIATE_128) ~= 0) then
--      return RandomSessionKey
--    elseif(bit.band(flags, NTLMSSP_NEGOTIATE_56) ~= 0) then
--      return string.sub(RandomSessionKey, 1, 6)
--    else
--      return string.sub(RandomSessionKey, 1, 4)
--    end
--
--    if(mode == "Client") then
--      return openssl.md5(SealKey .. "session key to client-to-server sealing key magic constant")
--    else
--      return openssl.md5(SealKey .. "session key to server-to-client sealing key magic constant")
--    end
--      return false, "Not implemented yet"
--
--    elseif(bit.band(self.flags, NTLMSSP_NEGOTIATE_LM_KEY) ~= 0) then
--      if(bit.band(self.flags, NTLMSSP_NEGOTIATE_56) ~= 0) then
--        return true, string.sub(self.random_session_key, 1, 6) .. "\xA0"
--      else
--        return true, string.sub(self.random_session_key, 1, 4) .. "\xE5\x38\xB0"
--      end
--    else
--      return true, self.random_session_key
--    end
--end,

  print = function(self)
    local status, LMv1 = self:LMOWFv1()
    local status, NTLMv1 = self:NTOWFv1()
    local status, LMv2 = self:LMOWFv2()
    local status, NTLMv2 = self:NTOWFv2()

    print("\n--------------------------------------")

    print("Domain:   " .. self:encode_string(self.domain)   .. "")
    nsedebug.print_hex(self:encode_string(self.domain))

    print("Username: " .. self:encode_string(self.username) .. "")
    nsedebug.print_hex(self:encode_string(self.username))

    print("Password: " .. self.password .. "")
    nsedebug.print_hex(self.password)

    print("Server Name: ")
    nsedebug.print_hex(self.server)

    print("Workstation Name: ")
    nsedebug.print_hex(self.workstation)

    print("Time: ")
    nsedebug.print_hex(bin.pack("<L", self.time))

    print("Client challenge: ")
    nsedebug.print_hex(self.client_challenge)

    print("Server challenge: ")
    nsedebug.print_hex(self.server_challenge)

    print("Flags: ")
    nsedebug.print_hex(bin.pack("<I", self.flags))

    print("LMOWFv1:  ")
    nsedebug.print_hex(LMv1)

    print("NTLMv1:  ")
    nsedebug.print_hex(NTLMv1)

    print("LMOWFv2:  ")
    nsedebug.print_hex(LMv2)

    print("NTLMv2:  ")
    nsedebug.print_hex(NTLMv2)

    print("--------------------------------------\n")
  end,

  test = function()
    local test = test.Test:new()

    -- [MS-NLMP] 4.2.1 defines these values
    local i = Ntlm:new('Domain\\User', 'Password')
    i:set_server("Server")
    i:set_workstation("COMPUTER")
    i:set_time(1)
    i:set_client_challenge("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa")
    i:set_server_challenge("\x01\x23\x45\x67\x89\xab\xcd\xef")
    i:set_random_session_key("\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55")
    -- [MS-NLMP] 4.2.2
    i:set_flags(bit.bor(NTLMSSP_NEGOTIATE_KEY_EXCH, NTLMSSP_NEGOTIATE_56, NTLMSSP_NEGOTIATE_128, NTLMSSP_NEGOTIATE_VERSION, NTLMSSP_TARGET_TYPE_SERVER, NTLMSSP_NEGOTIATE_ALWAYS_SIGN, NTLMSSP_NEGOTIATE_NTLM, NTLMSSP_NEGOTIATE_SEAL, NTLMSSP_NEGOTIATE_SIGN, NTLMSSP_NEGOTIATE_OEM, NTLMSSP_NEGOTIATE_UNICODE))
    i:print()

    -- [MS-NLMP] 4.2.2.1.1
    local status, result = i:LMOWFv1()
    test:check("LMOWFv1", result, "\xe5\x2c\xac\x67\x41\x9a\x9a\x22\x4a\x3b\x10\x8f\x3f\xa6\xcb\x6d", {binary = true})

    -- [MS-NLMP] 4.2.2.1.2
    local status, result = i:NTOWFv1()
    test:check("NTOWFv1", result, "\xa4\xf4\x9c\x40\x65\x10\xbd\xca\xb6\x82\x4e\xe7\xc3\x0f\xd8\x52", {binary = true})

    -- [MS-NLMP] 4.2.2.1.3
    local status, result = i:SessionBaseKey()
    test:check("SessionBaseKey", result, "\xd8\x72\x62\xb0\xcd\xe4\xb1\xcb\x74\x99\xbe\xcc\xcd\xf1\x07\x84", {binary = true})
    test:check("KeyExchangeKey", result, "\xd8\x72\x62\xb0\xcd\xe4\xb1\xcb\x74\x99\xbe\xcc\xcd\xf1\x07\x84", {binary = true})

    -- [MS-NLMP] 4.2.2.2
    local status, lm_response, ntlm_response = i:ComputeResponse()
    -- [MS-NLMP] 4.2.2.2.1
    test:check("NtChallengeResponse", ntlm_response, "\x67\xc4\x30\x11\xf3\x02\x98\xa2\xad\x35\xec\xe6\x4f\x16\x33\x1c\x44\xbd\xbe\xd9\x27\x84\x1f\x94", {binary = true})
    test:check("LmChallengeResponse", lm_response,   "\x98\xde\xf7\xb8\x7f\x88\xaa\x5d\xaf\xe2\xdf\x77\x96\x88\xa1\x72\xde\xf1\x1c\x7d\x5c\xcd\xef\x13", {binary = true})

    -- [MS-NLMP] 4.2.2.2.2
    local status, kxkey = i:KXKEY()
    test:check("KXKEY", lm_response,   "\x98\xde\xf7\xb8\x7f\x88\xaa\x5d\xaf\xe2\xdf\x77\x96\x88\xa1\x72\xde\xf1\x1c\x7d\x5c\xcd\xef\x13", {binary = true})
    i.flags = bit.bor(i.flags, NTLMSSP_NEGOTIATE_LM_KEY)
    local status, sealkey = i:KXKEY()
    test:check("KXKEY (LM_KEY)", sealkey, "\xb0\x9e\x37\x9f\x7f\xbe\xcb\x1e\xaf\x0a\xfd\xcb\x03\x83\xc8\xa0", {binary = true})
    i.flags = bit.band(i.flags, bit.bnot(NTLMSSP_NEGOTIATE_LM_KEY))

    -- [MS-NLMP] 4.2.2.2.3
    local result, kxkey = i:KXKEY()
    local rc4_handle = openssl.rc4(kxkey)
    local encrypted_session_key = rc4_handle(i.random_session_key)
    test:check("RandomSessionKey encrypted w/ KXKEY [1]", encrypted_session_key, "\x51\x88\x22\xb1\xb3\xf3\x50\xc8\x95\x86\x82\xec\xbb\x3e\x3c\xb7", {binary = true})

    i.flags = bit.bor(i.flags, NTLMSSP_NEGOTIATE_NON_NT_SESSION_KEY)
    local result, kxkey = i:KXKEY()
    local rc4_handle = openssl.rc4(kxkey)
    local encrypted_session_key = rc4_handle(i.random_session_key)
    test:check("RandomSessionKey encrypted w/ KXKEY [2]", encrypted_session_key, "\x74\x52\xca\x55\xc2\x25\xa1\xca\x04\xb4\x8f\xae\x32\xcf\x56\xfc", {binary = true})
    i.flags = bit.band(i.flags, bit.bnot(NTLMSSP_NEGOTIATE_NON_NT_SESSION_KEY))

    i.flags = bit.bor(i.flags, NTLMSSP_NEGOTIATE_LM_KEY)
    local result, kxkey = i:KXKEY()
    local rc4_handle = openssl.rc4(kxkey)
    local encrypted_session_key = rc4_handle(i.random_session_key)
    test:check("RandomSessionKey encrypted w/ KXKEY [3]", encrypted_session_key, "\x4c\xd7\xbb\x57\xd6\x97\xef\x9b\x54\x9f\x02\xb8\xf9\xb3\x78\x64", {binary = true})
    i.flags = bit.band(i.flags, bit.bnot(NTLMSSP_NEGOTIATE_LM_KEY))

    -- [MS-NLMP] 4.2.2.3
    i:parse_ntlm_challenge("\x4e\x54\x4c\x4d\x53\x53\x50\x00\x02\x00\x00\x00\x0c\x00\x0c\x00\x38\x00\x00\x00\x33\x82\x02\xe2\x01\x23\x45\x67\x89\xab\xcd\xef\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x70\x17\x00\x00\x00\x0f\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00")

    -- Flags from the example pcap (TODO: See why these don't match the flags I expect)
    i.flags = 0xe2808235
    local status, authenticate = i:get_ntlm_authenticate()
    test:check("ntlm_authenticate", authenticate, "\x4e\x54\x4c\x4d\x53\x53\x50\x00\x03\x00\x00\x00\x18\x00\x18\x00\x6c\x00\x00\x00\x18\x00\x18\x00\x84\x00\x00\x00\x0c\x00\x0c\x00\x48\x00\x00\x00\x08\x00\x08\x00\x54\x00\x00\x00\x10\x00\x10\x00\x5c\x00\x00\x00\x10\x00\x10\x00\x9c\x00\x00\x00\x35\x82\x80\xe2\x05\x01\x28\x0a\x00\x00\x00\x0f\x44\x00\x6f\x00\x6d\x00\x61\x00\x69\x00\x6e\x00\x55\x00\x73\x00\x65\x00\x72\x00\x43\x00\x4f\x00\x4d\x00\x50\x00\x55\x00\x54\x00\x45\x00\x52\x00\x98\xde\xf7\xb8\x7f\x88\xaa\x5d\xaf\xe2\xdf\x77\x96\x88\xa1\x72\xde\xf1\x1c\x7d\x5c\xcd\xef\x13\x67\xc4\x30\x11\xf3\x02\x98\xa2\xad\x35\xec\xe6\x4f\x16\x33\x1c\x44\xbd\xbe\xd9\x27\x84\x1f\x94\x51\x88\x22\xb1\xb3\xf3\x50\xc8\x95\x86\x82\xec\xbb\x3e\x3c\xb7", {binary = true})

    test:report()
  end
}

return _ENV;
