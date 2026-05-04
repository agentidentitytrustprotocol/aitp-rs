//! Spawn agent-b on a random port, run agent-a against it, assert the
//! demo prints a successful echo line.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn cargo_bin(name: &str) -> std::path::PathBuf {
    // The integration test binary is at:
    //   target/<profile>/deps/demo-<hash>
    // Sibling binaries built by the same `cargo test` invocation:
    //   target/<profile>/<name>
    // Walk up from the current exe to find them.
    let exe = std::env::current_exe().expect("test exe path");
    let parent = exe
        .parent() // .../deps/
        .and_then(|p| p.parent()) // .../debug/
        .expect("test exe lives under target/<profile>/deps/");
    let candidate = parent.join(name);
    if !candidate.exists() {
        panic!(
            "binary {} not found at {} — build with `cargo build -p aitp-example-two-agents`",
            name,
            candidate.display()
        );
    }
    candidate
}

fn pick_two_free_ports() -> (u16, u16) {
    let l1 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let l2 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let p1 = l1.local_addr().unwrap().port();
    let p2 = l2.local_addr().unwrap().port();
    drop(l1);
    drop(l2);
    (p1, p2)
}

#[test]
fn demo_runs_end_to_end() {
    let (port_a, port_b) = pick_two_free_ports();
    let mut bob = Command::new(cargo_bin("agent-b"))
        .arg("--port")
        .arg(port_b.to_string())
        .arg("--seed")
        .arg("integration-test-bob-seed")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agent-b");

    // Wait briefly for B's listener.
    std::thread::sleep(Duration::from_millis(300));

    let mut alice = Command::new(cargo_bin("agent-a"))
        .arg("--port")
        .arg(port_a.to_string())
        .arg("--peer")
        .arg(format!("http://localhost:{}", port_b))
        .arg("--seed")
        .arg("integration-test-alice-seed")
        .arg("--message")
        .arg("hello world")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agent-a");

    let started = Instant::now();
    let alice_status = loop {
        match alice.try_wait().expect("wait alice") {
            Some(s) => break s,
            None => {
                if started.elapsed() > Duration::from_secs(15) {
                    let _ = alice.kill();
                    let _ = bob.kill();
                    panic!("agent-a did not finish within 15s");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    };

    let mut alice_stdout = String::new();
    alice
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut alice_stdout)
        .ok();
    let mut alice_stderr = String::new();
    alice
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut alice_stderr)
        .ok();

    // Stop bob.
    let _ = bob.kill();
    let _ = bob.wait();

    assert!(
        alice_status.success(),
        "agent-a exited unsuccessfully\n--stdout--\n{alice_stdout}\n--stderr--\n{alice_stderr}",
    );
    assert!(
        alice_stdout.contains("/echo => 200"),
        "expected successful /echo response in stdout:\n{alice_stdout}\nstderr:\n{alice_stderr}"
    );
    assert!(
        alice_stdout.contains("echo from agent-b"),
        "expected echoed message body in stdout:\n{alice_stdout}"
    );
}
