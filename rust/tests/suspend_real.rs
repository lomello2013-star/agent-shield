use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use aidf_core::response::ProcessController;

#[test]
fn suspend_and_resume_real_process() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-tmp");
    std::fs::create_dir_all(&root).unwrap();
    let flag = root.join(format!("aidf-suspend-{}.bin", uuid::Uuid::new_v4()));
    let code = "import sys,time\nf=open(sys.argv[1],'ab')\nwhile True:\n    f.write(b'x'); f.flush(); time.sleep(0.02)\n";
    let mut child = Command::new("python")
        .arg("-c")
        .arg(code)
        .arg(&flag)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn child");
    thread::sleep(Duration::from_millis(500));
    let before = std::fs::metadata(&flag).unwrap().len();
    assert!(before > 0);

    let controller = ProcessController::new();
    controller.suspend(child.id()).expect("suspend");
    thread::sleep(Duration::from_millis(200));
    let frozen = std::fs::metadata(&flag).unwrap().len();
    thread::sleep(Duration::from_millis(400));
    assert_eq!(std::fs::metadata(&flag).unwrap().len(), frozen);

    controller.resume(child.id()).expect("resume");
    thread::sleep(Duration::from_millis(400));
    assert!(std::fs::metadata(&flag).unwrap().len() > frozen);

    let _ = child.kill();
    let _ = child.wait();
}
