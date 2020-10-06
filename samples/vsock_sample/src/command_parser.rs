use clap::ArgMatches;

const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;

#[derive(Debug, Clone)]
pub struct ServerArgs {
    pub cid: u32,
    pub port: u32,
}

impl ServerArgs {
    pub fn new_with(args: &ArgMatches) -> Result<Self, String> {
        Ok(ServerArgs {
            cid: parse_cid_server(args)?,
            port: parse_port(args)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ClientArgs {
    pub cid: u32,
    pub port: u32,
}

impl ClientArgs {
    pub fn new_with(args: &ArgMatches) -> Result<Self, String> {
        Ok(ClientArgs {
            cid: parse_cid_client(args)?,
            port: parse_port(args)?,
        })
    }
}

fn parse_cid_client(args: &ArgMatches) -> Result<u32, String> {
    let port = args.value_of("cid").ok_or("Could not find cid argument")?;
    port.parse()
        .map_err(|_err| "cid is not a number".to_string())
}

fn parse_cid_server(args: &ArgMatches) -> Result<u32, String> {
    if let Some(cid) = args.value_of("cid") {
        Ok(cid
            .parse()
            .map_err(|_err| "cid is not a number".to_string())?)
    } else {
        // If the cid argument is not provided, accept connections
        // from any CID
        Ok(VMADDR_CID_ANY)
    }
}

fn parse_port(args: &ArgMatches) -> Result<u32, String> {
    let port = args
        .value_of("port")
        .ok_or("Could not find port argument")?;
    port.parse()
        .map_err(|_err| "port is not a number".to_string())
}
