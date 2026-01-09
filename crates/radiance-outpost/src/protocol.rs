use rkyv::{Archive, Deserialize, Serialize};


#[derive(Archive, Deserialize, Serialize, Debug)]
#[rkyv(derive(Debug))]
pub enum ProtocolS2C {
    Tcp {
        data: Vec<u8>,
        id: u64,
    },
    TcpConnect {
        destination_host: String,
        destination_port: u16,
        id: u64,
    },
    TcpDisconnect {
        id: u64,
    },
    SignalFwdAdd {
        host: String,
        port: u16,
        req: u64,
    },
    SignalFwdRemove {
        host: String,
        port: u16,
        req: u64,
    },
    SignalFwdList {
        req: u64,
    },
    Dns {
        host: String,
        req: u64,
    },
}
#[derive(Archive, Deserialize, Serialize, Debug)]
pub enum ProtocolC2S {
    Tcp {
        source_host: String,
        source_port: u16,
        data: Vec<u8>,
        id: u64,
    },
    TcpConnect {
        id: u64,
    },
    TcpDisconnect {
        id: u64,
    },
    SignalFwdAdd {
        req: u64,
    },
    SignalFwdRemove {
        req: u64,
    },
    SignalFwdList {
        entries: Vec<(String, u16)>,
        req: u64,
    },
    Dns {
        host: String,
        ip: String,
        req: u64,
    },
    Identify,
}
#[derive(Archive, Deserialize, Serialize, Debug)]
#[rkyv(derive(Debug))]
pub struct StreamS2C {
    pub cid: u128,
    pub msg: ProtocolS2C,
}
#[derive(Archive, Deserialize, Serialize, Debug)]
pub struct StreamC2S {
    pub cid: u128,
    pub msg: ProtocolC2S,
}
#[derive(Archive, Deserialize, Serialize, Debug)]
pub struct DatagramMessage {
    pub cid: u128,
    pub data: Vec<u8>,
    pub host: String,
    pub port: u16,
}
