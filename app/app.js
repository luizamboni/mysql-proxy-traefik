const pcap = require('pcap');
const pcap_session = pcap.createSession("lo", { filter: 'port 3306'});

const INGONRE_TCP_HANDSHAKE = true
const INGONRE_TCP_END = true
const ONLY_PUSH = true


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

const connections = []

pcap_session.on('packet', function (raw_packet) {
    // do some stuff with a raw packet
    const packet = pcap.decode.packet(raw_packet);

    // console.log("\nethernet layer");
    // console.log(packet.payload.ethertype)

    // TCP package
    // console.log("\nip layer")

    // console.log("ip headerLength:", packet.payload.payload.headerLength);

    // application layer 
    // console.log("\ntcp layer");
    // console.log("tcp dataLength: ", packet.payload.payload.payload.dataLength);
    // console.log("tcp seqno: ", packet.payload.payload.payload.seqno);
    // console.log("tcp ackno: ", packet.payload.payload.payload.ackno);
 

    const tcp = packet.payload.payload.payload;

    let connection;

    // client init

    let pkg = null


    if (tcp.ackno === 0) {
        connection = new MysqlClientView(tcp.seqno)
        pkg = connection.clientSend(parseClientPackage(tcp))
        connections.push(connection)
    } else {
        // get any connection
        // TODO - make selection 
        connection = connections.find(Boolean);

        if (tcp.dport === 3306) {
            pkg = connection.clientSend(parseClientPackage(tcp))

        } else {
            pkg = connection.clientReceived(parseServerPackage(tcp))
        }        
    }
    outPutPkg(pkg) 


});

function outPutPkg(pkg) {
    console.log([
        '', pkg.direction,'\t' ,
        'confirmed:', pkg.confirmed, '\t',
        'ack:',       pkg.ackno, '\t',
        'seq:',       pkg.seqno , '\t',
        'length:',    pkg.dataLength, '\t',
        'flags:',     pkg.flags
    ].join(' '))
}

function parseServerPackage(tcp) {
    const { data: dataBuffer , ackno, seqno, dataLength } = tcp
    const flags = Object.keys(tcp.flags).filter(flag => tcp.flags[flag])

    let decoded = {}

    if (dataBuffer) {
        decoded = decodePacketfromServer(dataBuffer)
    }

    return {
        dataLength,
        ackno,
        seqno,
        flags,
        ...decoded
    }
}


function parseClientPackage(tcp) {
    const { data: dataBuffer , ackno, seqno, dataLength } = tcp
    const flags = Object.keys(tcp.flags).filter(flag => tcp.flags[flag])

    let decoded = {}
    if (dataBuffer) {
        decoded = decodePacketFromClient(dataBuffer)
    }

    return {
        dataLength,
        ackno,
        seqno,
        flags,
        ...decoded
    }
}

function decodePacketFromClient(data) {

    const payload_length =  data.readUInt8(0, 3);
    const sequence_id = data.readUIntBE(3, 1);
    const command = data.readUInt8(4);

    const payload = data.slice(5, 5 + payload_length);
    console.log("command: ",String(payload))
    return {
        raw: data,
        payload_length, 
        sequence_id, 
        command,
        command_label: mysql_enum_server_command[command],
        payload,
        payload_msg: String(payload),
    };
}

function decodePacketfromServer(data) {
    const header = data.slice(4,5).toString('hex')
    
    let responseType = null;

    if (header === '00' && data.length > 7 ) {
        responseType = 'OK'
    } else if (header === 'ff') {
        responseType = 'ERR'
    }

    return {
        responseType,
        raw: data,
        header
    }
}

class MysqlClientView {

    constructor(sequence) {
        this.connectionId = sequence;
        this.sequence = sequence;
        
        // start tcp connection
        this.connectinconnectiongg = false
        this.connected = false;

        // msyql authenticated
        this.authenticated = false;
        
        // end top connection
        this.disconnecting  = false
        this.finalized = false;

        
        // collection to see packets in order
        this.packages = []

        this.sendeds = []
        this.receiveds = []
    }

    init(pkg) {

        const payload = {
            direction: 'sended',
            confirmed: false,
            ...pkg
        }

        this.sendeds.push(payload)
        this.packages.push(payload)
    }

    _ackPhantonByte(collection, ackno) {
        const targeSendedSeqno = ackno - 1;
        const pkgConfirmed = collection.find(spkg => spkg.seqno === targeSendedSeqno)
        if (pkgConfirmed) {
            pkgConfirmed.confirmed = true
        }
    }

    clientSend(pkg) {
        
        // first package, not ack neno
        if (pkg.ackno === 0) {
            this.connecting = true
        } else if (pkg.flags.indexOf('ack') !== -1 && this.connecting && !this.connected) {
            this._ackPhantonByte(this.receiveds, pkg.ackno)
            this.connected = true
        } else if(pkg.flags.indexOf('fin') !== -1) {
            this._ackPhantonByte(this.receiveds, pkg.ackno)
            
        } else if (pkg.flags.indexOf('ack') !== -1 && pkg.flags.indexOf('psh') !== -1) {
            const pkgConfirmed = this.sendeds.find(p => p.ackno === pkg.ackno)
            if (pkgConfirmed) {
                pkgConfirmed.confirmed = true
            }
        } else {
            const targeSendedSeqno = pkg.ackno;
            const pkgConfirmed = this.receiveds.find(p => (p.seqno + p.dataLength) === targeSendedSeqno)
            if (pkgConfirmed) {
                pkgConfirmed.confirmed = true
            }
        }

        const payload = {
            direction: 'sended',
            confirmed: !!pkg.confirmed,
            ...pkg
        }

        this.sendeds.push(payload)
        this.packages.push(payload)
        return payload
    }

    clientReceived(pkg) {
        
        // connectiong phase
        if (pkg.flags.indexOf('syn') !== -1 && !this.connected) {
            const targeSendedSeqno = pkg.ackno - 1;
            const pkgConfirmed = this.sendeds.find(spkg => spkg.seqno === targeSendedSeqno)
            if (pkgConfirmed) {
                pkgConfirmed.confirmed = true
            }
        } else if (this.disconecting) {
            const targeSendedSeqno = pkg.ackno - 1;
            const pkgConfirmed = this.sendeds.find(spkg => spkg.seqno === targeSendedSeqno)
            if (pkgConfirmed) {
                pkgConfirmed.confirmed = true
            }

        } else if (pkg.flags.indexOf('ack') !== -1 && pkg.flags.indexOf('psh') !== -1) {
            const pkgConfirmed = this.receiveds.find(p => p.ackno === pkg.ackno)
            if (pkgConfirmed) {
                pkgConfirmed.confirmed = true
            }
        // middle phase
        } else {
            const targeSendedSeqno = pkg.ackno;
            const pkgConfirmed = this.sendeds.find(p => (p.seqno + p.dataLength) === targeSendedSeqno)
            if (pkgConfirmed) {
                pkgConfirmed.confirmed = true
            }
        }

        const payload = {
            direction: 'received',
            confirmed: !!pkg.confirmed,
            ...pkg
        }
        
        this.receiveds.push(payload)
        this.packages.push(payload)

        return payload
    }
}