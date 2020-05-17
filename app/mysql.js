const mysql_enum_server_command = [
    "COMSLEEP",
    "COM_QUIT",
    "COMINIT_DB",
    "COMQUERY",
    "COMFIELD_LIST",
    "COMCREATE_DB",
    "COMDROP_DB",
    "COMREFRESH",
    "COMDEPRECATED_1",
    "COMSTATISTICS",
    "COMPROCESS_INFO",
    "COMCONNECT",
    "COMPROCESS_KILL",
    "COMDEBUG",
    "COMPING",
    "COMTIME",
    "COMDELAYED_INSERT",
    "COMCHANGE_USER",
    "COMBINLOG_DUMP",
    "COMTABLE_DUMP",
    "COMCONNECT_OUT",
    "COMREGISTER_SLAVE",
    "COMSTMT_PREPARE",
    "COMSTMT_EXECUTE",
    "COMSTMT_SEND_LONG_DATA",
    "COMSTMT_CLOSE",
    "COMSTMT_RESET",
    "COMSET_OPTION",
    "COMSTMT_FETCH",
    "COMDAEMON",
    "COMBINLOG_DUMP_GTID",
    "COMRESET_CONNECTION",
    "COMEND",
]


/*
 adapted from:
 https://github.com/mysqljs/mysql/blob/e5a922bb09c4fa4c17997e4195b9f721dbd4ce4d/lib/protocol/Parser.js
*/

const MUL_32BIT            = Math.pow(2, 32);

function decodePacketFromClient(data) {
    let cursor = 0
    const payload_length = parseUnsignedNumber(cursor, data, 3)
    const sequence_id = parseUnsignedNumber(cursor += 3, data, 1)
    const command = data.readUInt8(cursor += 1);

    const payload = data.slice(cursor += 1, cursor + payload_length)
    const command_label = mysql_enum_server_command[command]
    return {
        header: {
            payload_length,
            sequence_id, 
        },
        command,
        command_label,
        raw: data,
        desc: [ command_label ,String(payload) ].join(' - ') ,
    };
}

function decodePacketfromServer(raw_data) {

    let cursor = 0

    const payload_length = parseUnsignedNumber(cursor, raw_data, 3)
    const sequence_id = parseUnsignedNumber((cursor += 3), raw_data, 1)

    // number of columns
    const number_of_fields =  parseUnsignedNumber((cursor += 1), raw_data, 1)

    debugger
    if (number_of_fields === 0x00) {
        return {
            type: 'ok',
            header: {
                payload_length,
                sequence_id,
            },
            payload: {
                firstByte: number_of_fields,
            },
            raw: raw_data,
            desc: "OK - packet"
        }
    }
    
    
    cursor  += 1
    

    const fields = []
    let fields_count = 0
    while(fields_count < number_of_fields) {
        const payload_length = parseUnsignedNumber(cursor, raw_data, 3)
        const sequence       = parseUnsignedNumber(3, raw_data, 1)
        const raw_packet     = raw_data.slice(cursor, cursor + payload_length + 4)

        console.log(raw_packet)
        eof = parseUnsignedNumber(4, raw_packet, 1)

        if (eof === 0xfe || eof === 0x00) {
            break;
        }

        const desc = parseString(4, raw_packet, payload_length)


        fields.push({
            header: {
                payload_length,
                sequence,
            },
            raw: raw_packet,
            desc,
        })

        cursor += 4 + payload_length

        fields_count++
    }


    const rows = []
    while(true) {
        const payload_length = parseUnsignedNumber(cursor, raw_data, 3)
        const raw_packet     = raw_data.slice(cursor, cursor + payload_length + 4)
        const sequence       = parseUnsignedNumber(3, raw_packet, 1)

        const eof = parseUnsignedNumber(4, raw_packet, 1)

        if (eof === 0xfe || eof === 0x00) {
            break;
        }

        const values = getRowsField(
            raw_packet.slice(4, 5 + payload_length)
        )
        
        rows.push({
            header: {
                payload_length,
                sequence,
            },
            values,
            raw: raw_packet
        })

        cursor += 4 + payload_length
    }

    return {
        header: {
            payload_length,
            sequence_id,
            number_of_fields,
        },
        fields,
        rows,
        raw: raw_data,
        desc: [ 
            'COMQUERY Response', 
            rows.map((f, i) => f.values.join(', ')).join(' | ')
        ].join(' - ')
    }
}


/**
 * 
 * @param {*} index index of init data
 * @param {*} buffer buffer
 * @param {*} bytes type of number
 */
function parseUnsignedNumber(index, buffer, bytes) {
    if (bytes === 1) {
      return buffer[index];
    }
  
    var offset = index + bytes - 1;
    var value  = 0;
  
    if (bytes > 4) {
      var err    = new Error('parseUnsignedNumber: Supports only up to 4 bytes');
      err.offset = (index - this._packetOffset - 1);
      err.code   = 'PARSER_UNSIGNED_TOO_LONG';
      throw err;
    }
  
    while (offset >= index) {
      value = ((value << 8) | buffer[offset]) >>> 0;
      offset--;
    }
  
    this._offset += bytes;
  
    return value;
}

function parseLengthCodedNumber(index, buffer) {
    if (index >= buffer.length) {
      var err    = new Error('Parser: read past end');
      err.code   = 'PARSER_READ_PAST_END';
      throw err;
    }
  
    const bits = buffer[index];
  
    if (bits <= 250) {
      return bits;
    }
  
    switch (bits) {
      case 251:
        return null;
      case 252:
        return parseUnsignedNumber(index + 1, buffer, 2);
      case 253:
        return parseUnsignedNumber(index + 1, buffer,3);
      case 254:
        break;
      default:
        var err    = new Error('Unexpected first byte' + (bits ? ': 0x' + bits.toString(16) : ''));
        err.code   = 'PARSER_BAD_LENGTH_BYTE';
        throw err;
    }
  
    var low = parseUnsignedNumber(index + 1, buffer,4);
    var high = parseUnsignedNumber(index + 1, buffer,4);
    var value;
  
    if (high >>> 21) {
      value = BigNumber(MUL_32BIT).times(high).plus(low).toString();
  
      if (this._supportBigNumbers) {
        return value;
      }
  
      var err    = new Error(
        'parseLengthCodedNumber: JS precision range exceeded, ' +
        'number is >= 53 bit: "' + value + '"'
      );
      err.code   = 'PARSER_JS_PRECISION_RANGE_EXCEEDED';
      throw err;
    }
  
    value = low + (MUL_32BIT * high);
  
    return value;
  };


function parseLengthCodedString(buffer) {
    const length = parseLengthCodedNumber(0, buffer);

    if (length === null) {
        return null;
    }

    return parseString(1, buffer, length);
}

function parseString(index, buffer, length) {
    const end = index + length;
    const value = buffer.toString('utf-8', index, end);
  
    return value;
}

function getRowsField(buffer) {
    
    const values = []
    let cursor = 0 
    while (cursor < buffer.length) {
        const field_length = buffer[cursor]
        const value = buffer.slice(cursor += 1, cursor += field_length).toString()
        values.push(value)        
    }

    return values
};

module.exports = {
    decodePacketFromClient,
    decodePacketfromServer,
}