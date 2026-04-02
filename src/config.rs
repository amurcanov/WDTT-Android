#[derive(Clone, Debug)]
pub struct CliArgs {
    pub peer_addr: String,
    pub vk_hashes: String,
    pub total_workers: usize,
    pub listen: String,
    pub sni: String,
    pub device_id: String,
    pub password: String,
    pub use_tcp: bool,
    pub use_udp: bool,
    pub vk_app_id: String,
    pub turn_host: String,
    pub turn_port: String,
    pub secondary_hash: String,
    pub vk_app_secret: String,
}

impl CliArgs {
    pub fn parse() -> Self {
        let mut args = Self {
            peer_addr: String::new(),
            vk_hashes: String::new(),
            total_workers: 24,
            listen: "127.0.0.1:9000".to_string(),
            sni: String::new(),
            device_id: "unknown".to_string(),
            password: String::new(),
            use_tcp: false,
            use_udp: false,
            vk_app_id: "6287487".to_string(),
            turn_host: String::new(),
            turn_port: String::new(),
            secondary_hash: String::new(),
            vk_app_secret: "QbYic1K3lEV5kTGiqlq2".to_string(),
        };

        let mut iter = std::env::args().skip(1);
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "-peer" | "--peer" => args.peer_addr = iter.next().unwrap_or_default(),
                "-vk" | "--vk" => args.vk_hashes = iter.next().unwrap_or_default(),
                "-n" | "--n" | "-workers" => {
                    args.total_workers = iter.next().unwrap_or_default().parse().unwrap_or(24)
                }
                "-listen" | "--listen" => args.listen = iter.next().unwrap_or_default(),
                "-sni" | "--sni" => args.sni = iter.next().unwrap_or_default(),
                "-device-id" | "--device-id" => args.device_id = iter.next().unwrap_or_default(),
                "-password" | "--password" => args.password = iter.next().unwrap_or_default(),
                "-tcp" | "--tcp" => args.use_tcp = true,
                "-udp" | "--udp" => args.use_udp = true,
                "-vk-app-id" => args.vk_app_id = iter.next().unwrap_or_default(),
                "-turn" => args.turn_host = iter.next().unwrap_or_default(),
                "-port" => args.turn_port = iter.next().unwrap_or_default(),
                "-vk2" => args.secondary_hash = iter.next().unwrap_or_default(),
                "-vk-app-secret" => args.vk_app_secret = iter.next().unwrap_or_default(),
                _ => {}
            }
        }
        args
    }
}

#[derive(Clone)]
pub struct TurnParams {
    pub host: String,
    pub port: String,
    pub hashes: Vec<String>,
    pub secondary_hash: String,
    pub sni: String,
}