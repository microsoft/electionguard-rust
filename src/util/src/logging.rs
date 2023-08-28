pub struct Logging {}

impl Logging {
    pub fn log(tag: &str, msg: &str, line: u32, file: &str) {
        println!("{}:{} [{}] {}", file, line, tag, msg);
    }
}
