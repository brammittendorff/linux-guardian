use crate::models::Finding;
use std::fs;

/// Check if a process is being traced (debugged) — breakpoints modify .text
pub(super) fn is_being_traced(pid: i32) -> bool {
    get_tracer_pid(pid) != 0
}

/// Get the PID of the process tracing `pid`. Returns 0 if not being traced.
fn get_tracer_pid(pid: i32) -> i32 {
    let status_path = format!("/proc/{}/status", pid);
    if let Ok(content) = fs::read_to_string(&status_path) {
        for line in content.lines() {
            if let Some(tracer) = line.strip_prefix("TracerPid:\t") {
                return tracer.trim().parse().unwrap_or(0);
            }
        }
    }
    0
}

/// Known legitimate debugger/tracer binary names
const KNOWN_DEBUGGERS: &[&str] = &[
    "gdb",
    "lldb",
    "strace",
    "ltrace",
    "perf",
    "valgrind",
    "rr",
    "ptrace",
    "lttng",
    // IDE debuggers
    "idea",
    "clion",
    "pycharm",
    "goland",
    "webstorm",
    "rider",
    "rustrover",
    "eclipse",
    "netbeans",
    "codelldb",
    "cppdbg",
    // Container runtimes (legitimately trace child processes)
    "runc",
    "crun",
    "containerd",
    "dockerd",
    "podman",
    // Profilers
    "sysprof",
    "heaptrack",
    "massif",
    "callgrind",
    "cachegrind",
    "hotspot",
    // Security tools
    "apparmor",
    "seccomp",
];

/// Validate WHO is tracing a process. If the tracer is not a known debugger,
/// it could be malware using ptrace to inject code or prevent analysis.
///
/// Returns a Finding if the tracer is suspicious.
pub(super) fn validate_tracer(pid: i32, comm: &str) -> Option<Finding> {
    let tracer_pid = get_tracer_pid(pid);
    if tracer_pid == 0 {
        return None;
    }

    // Identify the tracer process
    let tracer_exe = fs::read_link(format!("/proc/{}/exe", tracer_pid))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let tracer_comm = fs::read_to_string(format!("/proc/{}/comm", tracer_pid))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    // Check if tracer is a known debugger
    let tracer_base = tracer_exe.rsplit('/').next().unwrap_or(&tracer_exe);
    let is_known = KNOWN_DEBUGGERS.iter().any(|dbg| {
        tracer_base == *dbg || tracer_comm == *dbg || tracer_base.starts_with(&format!("{}-", dbg))
    });

    if is_known {
        return None;
    }

    Some(
        Finding::high(
            "suspicious_tracer",
            "Process Being Traced by Unknown Program",
            &format!(
                "Process '{}' (PID {}) is being traced by '{}' (PID {}, exe: {}). \
                 Known debuggers (gdb, lldb, strace, perf, etc.) were not detected. \
                 Malware uses ptrace to inject code or prevent analysis.",
                comm, pid, tracer_comm, tracer_pid, tracer_exe
            ),
        )
        .with_remediation(&format!(
            "Investigate tracer: ls -la /proc/{}/exe && cat /proc/{}/cmdline | tr '\\0' ' '",
            tracer_pid, tracer_pid
        )),
    )
}

/// Check whether a process is running in a different mount namespace from us.
///
/// Docker containers and other Linux namespaces have their own mount namespace.
/// When we open `/proc/PID/exe` on the host, the symlink resolves to the HOST
/// filesystem path (e.g. `/usr/bin/bash`). But the container loaded a DIFFERENT
/// binary from its own overlay filesystem — the host's `/usr/bin/bash` may be a
/// completely different build/version. Comparing the container's in-memory .text
/// against the host binary will always differ from byte 0.
///
/// We detect this by comparing the mount namespace inode of the target process
/// against our own. If they differ, the process is in a container and we must
/// access its binary through `/proc/PID/root/<path>` instead of the raw host path.
pub(super) fn is_in_different_mount_namespace(pid: i32) -> bool {
    let our_ns = fs::read_link("/proc/self/ns/mnt");
    let their_ns = fs::read_link(format!("/proc/{}/ns/mnt", pid));
    match (our_ns, their_ns) {
        (Ok(ours), Ok(theirs)) => ours != theirs,
        // If we can't read the namespace links, err on the side of caution and
        // assume same namespace (avoid spurious skips if permissions are limited).
        _ => false,
    }
}

/// Processes that legitimately modify their own executable memory.
/// JIT compilers, Electron/V8 apps, interpreters, emulators, and programs
/// using libraries like libffi create writable+executable pages or remap .text.
/// Flagging these would be false positives.
pub(super) fn is_known_self_modifying_process(comm: &str, exe_path: &str) -> bool {
    let comm_lc = comm.to_lowercase();
    let exe_lc = exe_path.to_lowercase();

    // -- Web browsers (all have JS JIT engines) --
    let browsers = [
        "chrome",
        "chromium",
        "firefox",
        "firefox-esr",
        "brave",
        "vivaldi",
        "opera",
        "msedge",
        "microsoft-edge",
        "epiphany",
        "gnome-web",
        "falkon",
        "midori",
        "qutebrowser",
        "thunderbird",
    ];

    // -- Electron/CEF apps (embed Chromium V8 JIT) --
    let electron = [
        "electron",
        "code",
        "code-oss",
        "cursor",
        "discord",
        "slack",
        "teams",
        "ms-teams",
        "spotify",
        "signal",
        "obsidian",
        "notion",
        "figma",
        "atom",
        "1password",
        "bitwarden",
        "skype",
        "skypeforlinux",
        "whatsapp",
        "whatsdesk",
        "postman",
        "insomnia",
        "gitkraken",
        "github-desktop",
        "element",
        "mattermost",
        "rocketchat",
        "wire",
        "keybase",
        "zulip",
        "hyper",
        "tabby",
        "logseq",
        "typora",
        "mailspring",
        "mongodb-compass",
        "etcher",
        "balena-etcher",
        "simplenote",
        "standard-notes",
        "todoist",
        "trello",
        "loom",
        "tidal-hifi",
        "cider",
        "nuclear",
        "youtube-music",
    ];

    // -- JavaScript runtimes --
    let js_runtimes = ["node", "nodejs", "deno", "bun", "graaljs"];

    // -- Language runtimes with JIT --
    let interpreters = [
        "python",
        "python3",
        "pypy",
        "pypy3",
        "ruby",
        "irb",
        "jruby",
        "truffle-ruby",
        "java",
        "javac",
        "javaw",
        "lua",
        "luajit",
        "php",
        "php-fpm",
        "php-cgi",
        "hhvm",
        "dotnet",
        "mono",
        "mono-sgen",
        "julia",
        "dart",
        "flutter",
        "erlang",
        "beam.smp",
        "elixir",
        "iex",
        "guile",
        "racket",
        "sbcl",
        "ghci",
        "gjs",
        "cjs",
        "numba",
        "perl",
        "r",
    ];

    // -- JVM-based IDEs and build tools --
    let jvm_tools = [
        "idea",
        "clion",
        "pycharm",
        "goland",
        "webstorm",
        "rider",
        "rustrover",
        "phpstorm",
        "datagrip",
        "eclipse",
        "netbeans",
        "android-studio",
        "gradle",
        "mvn",
        "sbt",
        "lein",
        "bazel",
    ];

    // -- Databases with JIT --
    let databases = [
        "postgres",
        "postgresql",
        "clickhouse",
        "clickhouse-server",
        "mongod",
        "mongos",
    ];

    // -- Emulators and dynamic binary translators --
    let emulators = [
        "qemu",
        "dolphin-emu",
        "pcsx2",
        "rpcs3",
        "ppsspp",
        "citra",
        "yuzu",
        "suyu",
        "sudachi",
        "ryujinx",
        "retroarch",
        "mupen64plus",
        "desmume",
        "melonds",
        "cemu",
        "flycast",
        "xemu",
        "mednafen",
        "dosbox",
        "dosbox-x",
        "dosbox-staging",
        "wine",
        "wine64",
        "wine-preloader",
        "proton",
        "box86",
        "box64",
        "fex",
    ];

    // -- Virtualization --
    let virt = ["virtualboxvm", "vboxheadless", "vboxsvc", "vmware-vmx"];

    // -- Desktop environments with JS engines --
    let desktop = [
        "gnome-shell",
        "cinnamon",
        "libreoffice",
        "soffice",
        "blender",
        "obs",
    ];

    // -- Debuggers and instrumentation --
    let debuggers = ["gdb", "lldb", "valgrind", "rr"];

    // -- WebAssembly runtimes --
    let wasm = ["wasmtime", "wasmer"];

    let all_lists: &[&[&str]] = &[
        &browsers,
        &electron,
        &js_runtimes,
        &interpreters,
        &jvm_tools,
        &databases,
        &emulators,
        &virt,
        &desktop,
        &debuggers,
        &wasm,
    ];

    for list in all_lists {
        for name in list.iter() {
            if comm_lc == *name
                || comm_lc.starts_with(&format!("{}-", name))
                || comm_lc.starts_with(&format!("{}.", name))
                || exe_lc.contains(&format!("/{}", name))
                || exe_lc.contains(&format!("/{}-", name))
            {
                return true;
            }
        }
    }

    // Crashpad handlers (Chrome, Electron apps)
    if comm_lc.contains("crashpad") || comm_lc.contains("chrome_crash") {
        return true;
    }

    // QEMU variants (qemu-system-x86_64, qemu-aarch64, etc.)
    if comm_lc.starts_with("qemu-") {
        return true;
    }

    // JetBrains IDEs often have versioned process names
    if exe_lc.contains("/jetbrains/") || exe_lc.contains("/idea") || exe_lc.contains("/pycharm") {
        return true;
    }

    false
}
