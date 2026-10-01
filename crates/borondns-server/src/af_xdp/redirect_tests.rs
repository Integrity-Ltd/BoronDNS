//! Privileged, wire-free differential checks. Run only in a disposable network
//! namespace with an up veth named `brdns-test`. Objects, fixtures and output
//! directory are explicit environment inputs; no host interface is attached.
use super::*;
use std::{fs, path::PathBuf, process::Command};

#[derive(serde::Deserialize)]
struct Case {
    name: String,
    packet: Vec<u8>,
    expected: u32,
}

#[derive(serde::Deserialize)]
struct Group {
    listener: SocketAddr,
    cases: Vec<Case>,
}

fn bpftool(args: &[&str]) -> serde_json::Value {
    let result = Command::new("bpftool")
        .arg("-j")
        .args(args)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}

#[test]
#[ignore = "requires root, isolated brdns-test veth, compiled objects and packet fixtures"]
fn redirect_objects_preserve_packet_decisions() {
    let control = fs::read(std::env::var("BORONDNS_BPF_CONTROL").unwrap()).unwrap();
    let candidate = fs::read(std::env::var("BORONDNS_BPF_CANDIDATE").unwrap()).unwrap();
    let groups: Vec<Group> =
        serde_json::from_slice(&fs::read(std::env::var("BORONDNS_BPF_CASES").unwrap()).unwrap())
            .unwrap();
    assert!(
        groups.len() >= 6,
        "must cover both families, wildcard and port zero"
    );
    let output = PathBuf::from(std::env::var("BORONDNS_BPF_OUTPUT").unwrap());
    fs::create_dir(&output).unwrap();
    let config = XdpConfig {
        umem_frame_count: 1024,
        rx_ring_size: 256,
        tx_ring_size: 256,
        fill_ring_size: 256,
        completion_ring_size: 256,
        ..Default::default()
    };
    let prepared = prepare_xdp_config(&config).unwrap();
    let umem = xdp::Umem::map(prepared.umem).unwrap();
    let mut builder = XdpSocketBuilder::new().unwrap();
    let (_rings, mut flags) = builder.build_wakable_rings(&umem, prepared.rings).unwrap();
    flags.force_copy();
    let nic = xdp::nic::NicIndex::lookup_by_name(&CString::new("brdns-test").unwrap())
        .unwrap()
        .unwrap();
    let socket = builder.bind(nic, 0, flags).unwrap();
    let mut checked = 0;
    for (variant, bytes, legacy_loader) in [
        ("control", &control, false),
        ("candidate", &candidate, false),
        ("candidate-legacy-loader", &candidate, true),
    ] {
        for (index, group) in groups.iter().enumerate() {
            let mut bpf = if legacy_loader {
                Ebpf::load(bytes).unwrap()
            } else {
                load_redirect_object(bytes, group.listener).unwrap()
            };
            Array::<_, RedirectConfig>::try_from(bpf.map_mut("REDIRECT_CONFIG").unwrap())
                .unwrap()
                .set(0, RedirectConfig::for_listener(group.listener), 0)
                .unwrap();
            let program: &mut Xdp = bpf
                .program_mut("borondns_xdp_redirect")
                .unwrap()
                .try_into()
                .unwrap();
            program.load().unwrap();
            let id = program.info().unwrap().id().to_string();
            // Prove the enabled candidate really uses frozen listener settings,
            // not merely an equivalent mutable-map lookup. Legacy combinations
            // keep the ordinary map configuration above.
            #[cfg(feature = "experimental-static-redirect")]
            if variant == "candidate" {
                let mut poison = RedirectConfig::for_listener(group.listener);
                poison.address_family = 0;
                Array::<_, RedirectConfig>::try_from(bpf.map_mut("REDIRECT_CONFIG").unwrap())
                    .unwrap()
                    .set(0, poison, 0)
                    .unwrap();
            }
            let dump = Command::new("bpftool")
                .args(["prog", "dump", "xlated", "id", &id])
                .output()
                .unwrap();
            assert!(dump.status.success());
            fs::write(
                output.join(format!("{variant}-{index}.xlated")),
                dump.stdout,
            )
            .unwrap();
            fs::write(
                output.join(format!("{variant}-{index}.json")),
                serde_json::to_vec_pretty(&bpftool(&["prog", "show", "id", &id])).unwrap(),
            )
            .unwrap();
            for populated in [false, true] {
                if populated {
                    XskMap::try_from(bpf.map_mut("BORONDNS_XSKS").unwrap())
                        .unwrap()
                        .set(0, socket.raw_fd(), 0)
                        .unwrap();
                }
                for case in &group.cases {
                    assert!(case.packet.len() >= 14, "test-run requires Ethernet header");
                    let path = output.join("packet.bin");
                    fs::write(&path, &case.packet).unwrap();
                    let result = bpftool(&[
                        "prog",
                        "run",
                        "id",
                        &id,
                        "data_in",
                        path.to_str().unwrap(),
                        "repeat",
                        "1",
                    ]);
                    let expected = if populated { case.expected } else { 2 };
                    assert_eq!(
                        result["retval"].as_u64().unwrap(),
                        u64::from(expected),
                        "{variant} {} {} populated={populated}",
                        group.listener,
                        case.name
                    );
                    checked += 1;
                }
            }
        }
    }
    assert!(checked >= 1000, "fixture coverage unexpectedly shrank");
    println!("redirect differential cases checked: {checked}");
}
