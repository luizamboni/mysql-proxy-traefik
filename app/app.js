const pcap = require('pcap');
const pcap_session = pcap.createSession("lo", { filter: 'port 3306'});
const tcp_tracker = new pcap.TCPTracker();
const { decodePacketFromClient, decodePacketfromServer } = require('./mysql')

/**
 * init pcap minitoring session
 */
pcap_session.on('packet', function (raw_packet) {
    const packet = pcap.decode.packet(raw_packet);
    tcp_tracker.track_packet(packet);
    // console.log(packet.payload.payload.payload.data)
});


/** 
 * this handle tcp handshake and teardown
 */

const ignorePatterm = /@@version_comment|mysql_native_password/

tcp_tracker.on('session', (session) => {
    console.log("Start of session between " + session.src_name + " and " + session.dst_name);
    
    session.on("data send", (tcp_session, chunk) => {
        try {
            const asText =  String(chunk)
            if (!ignorePatterm.test(asText) && asText) {
                console.log("\nsended:", decodePacketFromClient(chunk).desc)
            }
        } catch(err) {
            console.log("sended err:", err.message)
        }
    });


    session.on("data recv", (tcp_session, chunk) => {
        try {
            const asText =  String(chunk)
            if (!ignorePatterm.test(asText) && asText) {
                console.log("\nreceived:", decodePacketfromServer(chunk).desc)
            }
        } catch(err) {
            console.log("received err:", err.message)
        }
    });

    
    session.on('end', (session) => {
        console.log("End of TCP session between " + session.src_name + " and " + session.dst_name);
    });
});
