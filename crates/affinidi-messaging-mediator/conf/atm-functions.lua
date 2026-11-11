#!lua name=atm

-- Message records
--
-- A message id is the hash of the body alone (clients derive it from the
-- bytes), but one body may be stored for several recipients, and ownership,
-- queue entries, counters and expiry belong to one recipient. So each
-- recipient gets its own record:
--   MSG:<id>:<to>       body
--   MSG:META:<id>:<to>  metadata (BYTES, TO, FROM, TIMESTAMP, EXPIRES_AT,
--                       RECEIVE_ID, SEND_ID, delivery fields)
--   MSG:RCPT:<id>       set of recipients holding a record of <id>
-- Expiry buckets hold '<id>:<to>'. Inbox and outbox entries still carry the
-- plain id; the recipient is the inbox's owner, or the outbox entry's TO.
--
-- Records written before this layout are one per id (MSG:<id>,
-- MSG:META:<id>, bucket member '<id>') and stay readable and removable: a
-- recipient whose TO matches resolves to it. Nothing writes that layout any
-- more, so once every message stored before the upgrade has expired or been
-- removed no such key remains and the fallback can be dropped.

-- The metadata key suffix of the record of <id> held for <to>: '<id>:<to>',
-- or '<id>' for a legacy record whose TO is <to>. nil when there is none.
local function record_for(id, to)
    if redis.call('EXISTS', 'MSG:META:' .. id .. ':' .. to) == 1 then
        return id .. ':' .. to
    end
    if redis.call('HGET', 'MSG:META:' .. id, 'TO') == to then
        return id
    end
    return nil
end

-- Every record of <id>: { {suffix, meta}, ... }. Drops index members whose
-- record is gone (an interrupted write); they name nothing.
local function records_of(id)
    local found = {}
    local legacy = redis.call('HGETALL', 'MSG:META:' .. id)
    if next(legacy.map) ~= nil then
        table.insert(found, { id, legacy.map })
    end
    local members = redis.call('SMEMBERS', 'MSG:RCPT:' .. id)
    for to, _ in pairs(members.set) do
        local meta = redis.call('HGETALL', 'MSG:META:' .. id .. ':' .. to)
        if next(meta.map) == nil then
            redis.call('SREM', 'MSG:RCPT:' .. id, to)
        else
            table.insert(found, { id .. ':' .. to, meta.map })
        end
    end
    return found
end

-- store_message
-- keys = message_hash
-- args = [1] message
--        [2] expiry epoch at in seconds resolution
--        [3] message length in bytes
--        [4] to_did_hash
--        [5] from_did_hash <optional>
--        [6] receive_queue_maxlen <optional, 0 or absent = no limit>
local function store_message(keys, args)
    -- Do we have the correct number of arguments?
    -- from_did_hash can be optional!!! Means an anonymous message
    if #args < 4 or #args > 6 then
        return redis.error_reply('store_message: expected 4 to 6 arguments')
    end

    -- set response type to Version 3
    redis.setresp(3)

    -- Get current time on server
    local time = redis.call('TIME')
    local time = string.format("%d%03d", time[1], time[2] / 1000)
    local bytes = tonumber(args[3])
    if bytes == nil then
        return redis.error_reply('store_message: invalid bytes')
    end

    -- Stream MAXLEN for per-DID queues (0 = unlimited)
    local queue_maxlen = 0
    if #args >= 6 then
        queue_maxlen = tonumber(args[6]) or 0
    end

    -- Idempotent per recipient. A re-submitted message (the same bytes for
    -- the same recipient, e.g. an outbox re-send after a lost
    -- acknowledgement) is one record, queued and counted once. The same
    -- bytes for another recipient get a record of their own below.
    if record_for(keys[1], args[4]) ~= nil then
        return redis.status_reply('OK')
    end
    local record = keys[1] .. ':' .. args[4]

    -- Store message
    redis.call('SET', 'MSG:' .. record, args[1])

    -- Set Global Metrics
    redis.call('HINCRBY', 'GLOBAL', 'RECEIVED_BYTES', bytes)
    redis.call('HINCRBY', 'GLOBAL', 'RECEIVED_COUNT', 1)

    -- Create Message Expiry Record
    redis.call('ZADD', 'MSG_EXPIRY', 'NX', args[2], 'MSG_EXPIRY:' ..args[2])
    redis.call('SADD', 'MSG_EXPIRY:' ..args[2], record)

    -- Update the receiver records
    redis.call('HINCRBY', 'DID:' .. args[4], 'RECEIVE_QUEUE_BYTES', bytes)
    redis.call('HINCRBY', 'DID:' .. args[4], 'RECEIVE_QUEUE_COUNT', 1)

    -- XADD with optional MAXLEN to bound per-DID stream growth
    local RQ
    if queue_maxlen > 0 then
        RQ = redis.call('XADD', 'RECEIVE_Q:' .. args[4], 'MAXLEN', '~', queue_maxlen, time .. '-*',
            'MSG_ID', keys[1], 'BYTES', bytes, 'FROM', args[5])
    else
        RQ = redis.call('XADD', 'RECEIVE_Q:' .. args[4], time .. '-*',
            'MSG_ID', keys[1], 'BYTES', bytes, 'FROM', args[5])
    end

    -- Update the sender records
    local SQ = nil
    if #args >= 5 and args[5] ~= nil and args[5] ~= "ANONYMOUS" then
        -- Update the sender records
        redis.call('HINCRBY', 'DID:' .. args[5], 'SEND_QUEUE_BYTES', bytes)
        redis.call('HINCRBY', 'DID:' .. args[5], 'SEND_QUEUE_COUNT', 1)
        -- Per-relationship depth: one hash per sender, one field per recipient.
        -- The per-DID total above cannot tell fan-out from flooding; this can.
        redis.call('HINCRBY', 'PEER_Q:' .. args[5], args[4], 1)
        if queue_maxlen > 0 then
            SQ = redis.call('XADD', 'SEND_Q:' .. args[5], 'MAXLEN', '~', queue_maxlen, time .. '-*',
                'MSG_ID', keys[1], 'BYTES', bytes, 'TO', args[4])
        else
            SQ = redis.call('XADD', 'SEND_Q:' .. args[5], time .. '-*',
                'MSG_ID', keys[1], 'BYTES', bytes, 'TO', args[4])
        end
    end

    -- Update message MetaData
    redis.call('HSET', 'MSG:META:' .. record, 'BYTES', bytes, 'TO', args[4], 'TIMESTAMP', time,
        'RECEIVE_ID', RQ, 'EXPIRES_AT', args[2])
    if SQ ~= nil then
        redis.call('HSET', 'MSG:META:' .. record, 'FROM', args[5], 'SEND_ID', SQ)
    end
    redis.call('SADD', 'MSG:RCPT:' .. keys[1], args[4])

    return redis.status_reply('OK')
end

-- Removes one record and everything it holds. meta is its metadata map.
-- Returns { TO, FROM or '', BYTES, '1' when it sat in an outbox else '0' }.
local function remove_record(id, suffix, meta)
    local bytes = meta.BYTES

    -- Delete message
    redis.call('DEL', 'MSG:' .. suffix)

    -- Set Global Metrics
    redis.call('HINCRBY', 'GLOBAL', 'DELETED_BYTES', bytes)
    redis.call('HINCRBY', 'GLOBAL', 'DELETED_COUNT', 1)

    -- Remove the receiver records
    redis.call('HINCRBY', 'DID:' .. meta.TO, 'RECEIVE_QUEUE_BYTES', -bytes)
    redis.call('HINCRBY', 'DID:' .. meta.TO, 'RECEIVE_QUEUE_COUNT', -1)
    redis.call('XDEL', 'RECEIVE_Q:' .. meta.TO, meta.RECEIVE_ID)

    -- Remove the sender records
    local outbox = '0'
    if meta.SEND_ID ~= nil then
        redis.call('HINCRBY', 'DID:' .. meta.FROM, 'SEND_QUEUE_BYTES', -bytes)
        redis.call('HINCRBY', 'DID:' .. meta.FROM, 'SEND_QUEUE_COUNT', -1)
        -- Per-relationship depth. HDEL at zero so a sender that has messaged
        -- many peers does not keep a field for each of them forever.
        local peer_left = redis.call('HINCRBY', 'PEER_Q:' .. meta.FROM, meta.TO, -1)
        if tonumber(peer_left) <= 0 then
            redis.call('HDEL', 'PEER_Q:' .. meta.FROM, meta.TO)
        end
        redis.call('XDEL', 'SEND_Q:' .. meta.FROM, meta.SEND_ID)
        outbox = '1'
    end

    -- Remove the message metadata, its recipient index entry and its
    -- current expiry entry (earlier entries are dropped by the sweeper)
    redis.call('DEL', 'MSG:META:' .. suffix)
    if suffix ~= id then
        redis.call('SREM', 'MSG:RCPT:' .. id, meta.TO)
    end
    if meta.EXPIRES_AT ~= nil then
        redis.call('SREM', 'MSG_EXPIRY:' .. meta.EXPIRES_AT, suffix)
    end

    return { meta.TO, meta.FROM or '', tostring(bytes), outbox }
end

-- delete_message
-- keys = message_hash
-- args = [1] did_hash (requesting deletion)
--        [2] admin_did_hash (the mediator's admin DID hash, for permission
--            check; '' for none)
--        [3] scope: 'R' the record held for [4], 'P' the records in [4]'s
--            queues (its own inbox copy, else every copy it sent), 'A' every
--            record (admin only). Default: 'A' for an admin, else 'P' of [1].
--        [4] scope did_hash
--        [5] expiry slot (epoch seconds) when the expiry sweep is deleting:
--            a record whose current expiry is later is not due and is left
--            alone ('' for none)
-- Returns one { TO, FROM, BYTES, OUTBOX } per removed record. The rules are
-- the same as `ops::select_records` in the Rust backends.
local function delete_message(keys, args)
    -- Correct number of keys?
    if #keys ~= 1 then
        return redis.error_reply('delete_message: only accepts one key')
    end

    -- Correct number of args?
    if #args < 1 or #args > 5 then
        return redis.error_reply('delete_message: Requires 1-5 arguments')
    end

    -- set response type to Version 3
    redis.setresp(3)

    local id = keys[1]
    local requester = args[1]
    local is_admin = (#args >= 2 and args[2] ~= '' and args[1] == args[2])
    local scope = args[3] or ''
    local scope_did = args[4] or ''
    if scope == '' then
        if is_admin then scope = 'A' else scope = 'P' end
        scope_did = requester
    end
    if scope == 'A' and not is_admin then
        scope = 'P'
        scope_did = requester
    end

    local chosen = {}
    if scope == 'R' or scope == 'P' then
        local own = record_for(id, scope_did)
        if own ~= nil then
            local meta = redis.call('HGETALL', 'MSG:META:' .. own)
            table.insert(chosen, { own, meta.map })
        end
    end
    if scope ~= 'R' and #chosen == 0 then
        local all = records_of(id)
        for _, record in ipairs(all) do
            if scope == 'A' or record[2].FROM == scope_did then
                table.insert(chosen, record)
            end
        end
    end
    -- Nothing in the queues asked about: not found, even when other accounts
    -- hold copies under the id (a second delete of one's own copy is
    -- "already gone", and a non-party learns nothing of other accounts).
    if #chosen == 0 then
        return redis.error_reply('NOT_FOUND: message_hash (' .. id .. ')')
    end

    for _, record in ipairs(chosen) do
        local meta = record[2]
        -- Allowed if: requester is TO, requester is FROM, or requester is the admin
        if not (is_admin or meta.TO == requester or meta.FROM == requester) then
            return redis.error_reply('PERMISSION_DENIED: Requesting DID does not have ownership of this message')
        end
        if meta.BYTES == nil then
            redis.log(redis.LOG_WARNING, 'message (' .. record[1] .. ') metadata did not contain BYTES field.')
            return redis.error_reply('message (' .. record[1] .. ') metadata did not contain BYTES field.')
        end
        -- An expiry entry left by a deadline the record no longer has (an
        -- earlier copy of the same bytes, or the original deadline of one
        -- brought forward) must not remove it. Legacy records carry no
        -- EXPIRES_AT and are due, as before.
        if #args >= 5 and args[5] ~= '' and meta.EXPIRES_AT ~= nil then
            local expires = tonumber(meta.EXPIRES_AT) or 0
            if expires == 0 or expires > tonumber(args[5]) then
                return redis.error_reply('NOT_FOUND: message_hash (' .. id .. ') is not due at this expiry')
            end
        end
    end

    local removed = {}
    for _, record in ipairs(chosen) do
        table.insert(removed, remove_record(id, record[1], record[2]))
    end
    return removed
end

-- fetch_messages
-- keys = did_hash
-- args = [1] start_id
--        [2] limit
local function fetch_messages(keys, args)
    -- Do we have the correct number of arguments?
    if #args ~= 2 then
        return redis.error_reply('fetch_messages: wrong arguments')
    end

    -- set response type to Version 3
    redis.setresp(3)

    -- Prepend an exclusive start_id if it exists
    local start_id = '-'
    if args[1] ~= "-" then
        start_id = '(' .. args[1]
    end

    -- Get list of messages from stream
    local list = redis.call('XRANGE', 'RECEIVE_Q:' .. keys[1], start_id, '+', 'COUNT', args[2])

    local fetched_messages = {}
    for x, element in ipairs(list) do
        -- element[1] = stream_id
        -- element[2] = fields: [MSG_ID, id, BYTES, bytes, FROM, from]
        local fields = element[2]
        local msg_id = fields[2]
        fetched_messages[x] = { 'STREAM_ID', element[1], 'MSG_ID', msg_id, 'FROM_DID', fields[6] }

        -- This recipient's record of the message
        local record = record_for(msg_id, keys[1])
        if record ~= nil then
            local body = redis.call('GET', 'MSG:' .. record)
            if body then
                table.insert(fetched_messages[x], 'MSG')
                table.insert(fetched_messages[x], body)
            end

            local meta = redis.call('HGETALL', 'MSG:META:' .. record)
            for k, v in pairs(meta.map) do
                table.insert(fetched_messages[x], 'META_' .. k)
                table.insert(fetched_messages[x], v)
            end
        end
    end -- end of XRANGE list

    return fetched_messages
end

-- clean_start_streaming
-- keys = uuid
-- returns number of sessions cleaned up
local function clean_start_streaming(keys, args)
    -- Correct number of keys?
    if #keys ~= 1 then
        return redis.error_reply('clean_start_streaming: only accepts one key')
    end

    -- Correct number of args?
    if #args ~= 0 then
        return redis.error_reply('clean_start_streaming: No arguments required')
    end

    -- set response type to Version 3
    redis.setresp(3)

    local key = 'STREAMING_SESSIONS:' .. keys[1]

    -- Clean up sessions in batches to avoid blocking the Redis event loop
    local counter = 0
    local max_batch = 500
    while (counter < max_batch) do
        local response = redis.call('SPOP', key, 1)

        -- No more items in the set
        if next(response.set) == nil then
            break
        end

        local session = nil
        for k, v in pairs(response.set) do
            session = k
            counter = counter + 1
        end

        -- remove from global session list, unless another instance has
        -- taken the DID since: its entry is not ours to clean
        local owner = redis.call('HGET', 'GLOBAL_STREAMING', session)
        if owner and string.match(owner, '^([^:]*):') == keys[1] then
            redis.call('HDEL', 'GLOBAL_STREAMING', session)
            redis.call('HDEL', 'STREAMING_KIND', session)
        end
    end

    return counter
end

-- get_status_reply
-- keys = did_hash that we are getting status for
-- returns Message Pickup 3.0 Status details
local function get_status_reply(keys, args)
    -- Correct number of keys?
    if #keys ~= 1 then
        return redis.error_reply('get_status_reply: only accepts one key (recipient_did_hash)')
    end

    -- Correct number of args?
    if #args ~= 0 then
        return redis.error_reply('get_status_reply: No arguments required')
    end

    -- set response type to Version 3
    redis.setresp(3)

    local response = {}
    response.map = {}
    response.map.recipient_did = keys[1]

    -- Set the message count and total bytes
    local r = redis.call('HMGET', 'DID:' .. keys[1], 'RECEIVE_QUEUE_COUNT', 'RECEIVE_QUEUE_BYTES')
    response.map.message_count = tonumber(r[1])
    response.map.total_bytes = tonumber(r[2])

    -- Get the oldest and newest message information
    local r = redis.pcall('XINFO', 'STREAM', 'RECEIVE_Q:' .. keys[1])
    if r['err'] == nil and r.map then
        response.map.oldest_received = r.map['first-entry'] and r.map['first-entry'][1] or 0
        response.map.newest_received = r.map['last-entry'] and r.map['last-entry'][1] or 0
        response.map.queue_count = r.map['length']
    end

    -- Get live streaming status
    local r = redis.call("HEXISTS", "GLOBAL_STREAMING", keys[1])
    if r == 0 then
        response.map.live_delivery = false
    else
        response.map.live_delivery = true
    end

    return response
end

redis.register_function('store_message', store_message)
redis.register_function('delete_message', delete_message)
redis.register_function('fetch_messages', fetch_messages)
redis.register_function('clean_start_streaming', clean_start_streaming)
redis.register_function('get_status_reply', get_status_reply)
