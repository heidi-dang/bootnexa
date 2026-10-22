use std::process::Command;
#[test]
fn read_only_probe_refuses_target_or_write_commands_before_enumeration() {
    let binary = env!("CARGO_BIN_EXE_bootnexa-safety-probe");
    for args in [
        &["--write"][..],
        &["--erase", "1"][..],
        &["--probe", "\\\\.\\PhysicalDrive1"][..],
        &[][..],
    ] {
        let output = Command::new(binary)
            .args(args)
            .output()
            .expect("probe executable starts");
        assert_eq!(
            output.status.code(),
            Some(2),
            "CLI must refuse all target/write arguments"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stdout.is_empty());
        assert!(stderr.contains("read-only"));
    }
}
#[cfg(not(windows))]
#[test]
fn windows_probe_fails_closed_off_windows() {
    let output = Command::new(env!("CARGO_BIN_EXE_bootnexa-safety-probe"))
        .arg("--probe")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
}
