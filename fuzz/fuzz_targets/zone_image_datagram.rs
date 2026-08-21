#![no_main]

use std::{
    hint::black_box,
    sync::{Once, OnceLock},
};

use borondns_core::{
    dns::{
        AnswerOptions, AnyResponseMode, DEFAULT_MAX_UDP_PAYLOAD, DatagramAction, DomainName,
        Header, LookupResult, Question, RecordType, Transport,
        answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image,
        default_zone_image_provider,
    },
    zone::{ResourceRecord, Rrset, ZoneSnapshot, ZoneStore},
    zone_image::{ZoneImagePlanSectionSummary, ZoneImagePlanSummary},
};
use libfuzzer_sys::fuzz_target;

const QID: u16 = 0x5a11;
const QCLASS_IN: u16 = 1;
const QCLASS_ANY: u16 = 255;

fuzz_target!(|data: &[u8]| {
    // Preserve arbitrary wire/parser coverage independently of the valid
    // semantic-query generator below.
    exercise_packet(data, answer_options(data));

    exercise_regression_seeds_once();
    let _ = exercise_shaped_query(data);
});

fn exercise_packet(packet: &[u8], options: AnswerOptions<'_>) -> DatagramAction {
    answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image(
        packet,
        zones(),
        options,
        |qname, qclass| {
            black_box((qname, qclass));
            true
        },
        |qname, qclass, serial| {
            black_box((qname, qclass, serial));
        },
        |metrics| {
            black_box(metrics);
        },
        &default_zone_image_provider,
    )
}

fn exercise_shaped_query(data: &[u8]) -> Header {
    let packet = shaped_query_packet(data);
    let request_header = Header::parse(&packet).expect("shaped header is valid");
    let question = Question::parse(&packet).expect("shaped question is valid");
    let options = answer_options(data);
    let edns_well_formed = shaped_edns_well_formed(data, options.transport);
    // The production query path consults authoritative zone data only for IN
    // and ANY. CHAOS is answered separately and every other QCLASS is refused
    // before ZoneStore/ZoneImage lookup, so direct image/oracle equivalence is
    // neither required nor observable for those classes.
    let plan_summary = (edns_well_formed && matches!(question.qclass, QCLASS_IN | QCLASS_ANY))
        .then(|| {
            assert_zone_image_matches_offline_oracle(
                &question,
                options,
                shaped_dnssec_requested(data),
            )
        });

    let DatagramAction::Respond(response) = exercise_packet(&packet, options) else {
        panic!("valid authoritative query was discarded");
    };
    let response_header = Header::parse(&response).expect("response header is valid");
    assert_eq!(response_header.id, request_header.id);
    assert!(response_header.is_response());
    if !edns_well_formed {
        assert_eq!(
            response_header.flags & 0x000f,
            borondns_core::dns::Rcode::FormErr as u16,
            "malformed EDNS must be rejected before QCLASS and zone lookup"
        );
        assert_eq!(response_header.flags & 0x0400, 0);
    } else if let Some(plan_summary) = plan_summary {
        assert_eq!(
            response_header.flags & 0x000f,
            (plan_summary.rcode as u16) & 0x000f
        );
        assert_eq!(
            response_header.flags & 0x0400 != 0,
            plan_summary.authoritative
        );
    } else {
        assert_eq!(
            response_header.flags & 0x000f,
            borondns_core::dns::Rcode::Refused as u16,
            "fixture names are not CHAOS diagnostics and unsupported QCLASS must be refused"
        );
        assert_eq!(response_header.flags & 0x0400, 0);
    }

    if options.transport == Transport::Udp {
        let advertised_payload = if byte(data, 13) & 1 == 0 {
            512
        } else {
            512 + (get_u16(data, 14) % 1232)
        };
        let ceiling = usize::from(advertised_payload.min(options.max_udp_payload));
        assert!(response.len() <= ceiling);
    } else {
        assert_eq!(response_header.flags & 0x0200, 0);
    }
    response_header
}

fn assert_zone_image_matches_offline_oracle(
    question: &Question,
    options: AnswerOptions<'_>,
    dnssec_requested: bool,
) -> ZoneImagePlanSummary {
    let published = zones()
        .find_published_zone(&question.qname)
        .expect("shaped query is inside fixture zone");
    let image = published.active_zone_image_ref();
    let mut plan = image.lookup_response_plan(
        &question.qname,
        question.qtype,
        question.qclass,
        options.max_cname_chain,
        options.any_response,
    );
    let base_image_summary = image.plan_summary(&plan).expect("image plan summarizes");
    let snapshot = fixture()
        .snapshots
        .iter()
        .find(|snapshot| question.qname.is_equal_or_subdomain_of(snapshot.origin()))
        .expect("shaped query has a fixture snapshot");
    let oracle_lookup = snapshot.offline_oracle().lookup_with_options(
        &question.qname,
        question.qtype,
        question.qclass,
        options.max_cname_chain,
        options.any_response,
    );
    assert_eq!(base_image_summary, lookup_summary(&oracle_lookup));
    if dnssec_requested {
        plan = image.augment_lookup_plan_with_dnssec(
            plan,
            &question.qname,
            question.qclass,
            options.nsec3_max_iterations,
        );
    }
    image
        .plan_summary(&plan)
        .expect("augmented image plan summarizes")
}

struct Fixture {
    store: ZoneStore,
    snapshots: Vec<ZoneSnapshot>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let apex = DomainName::from_absolute_str("zoneimage.test.").expect("static apex is valid");
        let snapshots = vec![
            zone_snapshot(apex),
            nsec3_zone_snapshot(name("nsec3.test.")),
        ];
        let store = ZoneStore::new();
        for snapshot in &snapshots {
            store
                .try_insert_snapshot(snapshot.clone())
                .expect("static fuzz zone compiles");
        }
        Fixture { store, snapshots }
    })
}

fn zones() -> &'static ZoneStore {
    &fixture().store
}

fn exercise_regression_seeds_once() {
    static REGRESSION_SEEDS: Once = Once::new();
    REGRESSION_SEEDS.call_once(|| {
        for (index, seed) in regression_seeds().iter().enumerate() {
            let response_header = exercise_shaped_query(seed);
            if index == 6 {
                assert_ne!(
                    response_header.flags & 0x0200,
                    0,
                    "bulk ANY regression query must exercise UDP truncation"
                );
            }
        }
    });
}

fn regression_seeds() -> [[u8; 32]; 13] {
    let mut seeds = [[0u8; 32]; 13];

    // CNAME, wildcard synthesis, DNAME synthesis, referral, ANY/full,
    // DNSSEC/EDNS denial, UDP truncation, and QCLASS=ANY.
    seeds[0][4] = 2;
    seeds[1][4] = 9;
    seeds[2][4] = 10;
    seeds[3][4] = 12;
    seeds[4][5] = 11;
    seeds[4][27] = 1;
    seeds[5][4] = 14;
    seeds[5][13] = 1;
    seeds[5][16] = 1;
    seeds[6][4] = 15;
    seeds[6][5] = 11;
    seeds[6][27] = 1;
    seeds[7][4] = 1;
    seeds[7][8] = 0x80;
    seeds[7][10] = 0xff;
    // Retained-corpus regression: apex/CNAME/QCLASS=0 must follow the
    // production REFUSED path rather than comparing unreachable lookup plans.
    seeds[8][..9].copy_from_slice(&[0x6e, 0x73, 0xff, 0xff, 0xff, 0xff, 0x0a, 0x31, 0xeb]);
    // Retained-corpus regression: malformed three-byte COOKIE EDNS data must
    // produce FORMERR before this unsupported QCLASS can produce REFUSED.
    seeds[9][..23].copy_from_slice(&[
        0x74, 0x50, 0x06, 0x10, 0x74, 0x50, 0x06, 0x10, 0xff, 0xff, 0xff, 0x64, 0xa2, 0x03, 0x00,
        0xff, 0xff, 0xff, 0x64, 0xa2, 0x03, 0x00, 0x0a,
    ]);
    // NSEC3 NXDOMAIN with EDNS DO reaches the indexed hash-ring proof path.
    seeds[10][4] = 17;
    seeds[10][13] = 1;
    seeds[10][16] = 1;
    // Retained-corpus regression: a DO=1 NSEC3 NXDOMAIN whose synthetic ring
    // lacks an exact closest-encloser proof is deliberately converted from the
    // base NXDOMAIN plan to SERVFAIL by DNSSEC augmentation. Compare the
    // production response with the augmented plan, not the pre-DNSSEC oracle.
    seeds[11][..17].copy_from_slice(&[
        0x00, 0xf1, 0x0a, 0xf1, 0x3b, 0x30, 0x2b, 0x1c, 0x3c, 0x3c, 0x53, 0xff, 0x00, 0xff, 0x2e,
        0x2d, 0x2f,
    ]);
    // Retained-corpus regression: a nonempty TCP Keepalive request option is
    // malformed and produces FORMERR before the otherwise valid zone lookup.
    seeds[12].copy_from_slice(&[
        0x2d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8c, 0x00, 0x00, 0x00, 0xdd, 0xdd,
        0x00, 0xdd, 0xdd, 0xdd, 0xdd, 0x01, 0x00, 0x0b, 0xf2, 0x58, 0xf1, 0x74, 0x2d, 0xdd, 0xdd,
        0xdd, 0x00,
    ]);
    seeds
}

fn shaped_edns_well_formed(data: &[u8], transport: Transport) -> bool {
    if byte(data, 13) & 1 == 0 {
        return true;
    }
    let option_len = usize::from(byte(data, 20).min(32));
    if option_len == 0 {
        return true;
    }
    let option_code = get_u16(data, 21);
    // The shaped generator emits one exactly framed option. Of the option
    // codes interpreted by the server, only COOKIE imposes a payload length:
    // 8 bytes for a client cookie, or 8 plus a 8..=32 byte server cookie.
    match option_code {
        10 => option_len == 8 || (16..=40).contains(&option_len),
        11 => option_len == 0 || transport == Transport::Udp,
        _ => true,
    }
}

fn shaped_dnssec_requested(data: &[u8]) -> bool {
    byte(data, 13) & 1 != 0 && byte(data, 16) & 1 != 0
}

fn lookup_summary(lookup: &LookupResult) -> ZoneImagePlanSummary {
    ZoneImagePlanSummary {
        rcode: lookup.rcode,
        authoritative: lookup.authoritative,
        answers: records_summary(&lookup.answers),
        authorities: records_summary(&lookup.authorities),
        additionals: records_summary(&lookup.additionals),
        termination: lookup.termination,
        nsec3_iterations_exceeded: lookup.nsec3_iterations_exceeded,
    }
}

fn records_summary(records: &[ResourceRecord]) -> ZoneImagePlanSectionSummary {
    const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;

    let mut digest = FNV_OFFSET_BASIS;
    for record in records {
        let mut record_digest = FNV_OFFSET_BASIS;
        record_digest = fnv1a_bytes(record_digest, record.owner.canonical_key().as_bytes());
        record_digest = fnv1a_bytes(record_digest, &record.rr_type.to_be_bytes());
        record_digest = fnv1a_bytes(record_digest, &record.class.to_be_bytes());
        record_digest = fnv1a_bytes(record_digest, &record.ttl.to_be_bytes());
        record_digest = fnv1a_bytes(record_digest, &(record.rdata.len() as u64).to_be_bytes());
        record_digest = fnv1a_bytes(record_digest, &record.rdata);
        digest = fnv1a_bytes(digest, &record_digest.to_be_bytes());
    }
    ZoneImagePlanSectionSummary {
        count: records.len(),
        digest,
    }
}

fn fnv1a_bytes(mut digest: u64, bytes: &[u8]) -> u64 {
    const FNV_PRIME: u64 = 0x100000001b3;

    for byte in bytes {
        digest ^= u64::from(*byte);
        digest = digest.wrapping_mul(FNV_PRIME);
    }
    digest
}

fn zone_snapshot(apex: DomainName) -> ZoneSnapshot {
    ZoneSnapshot::active(
        apex.clone(),
        Some(1),
        vec![
            rrset(&apex, RecordType::Soa, vec![soa_rdata(1)]),
            rrset(
                &apex,
                RecordType::Ns,
                vec![name_wire("ns1.zoneimage.test.")],
            ),
            rrset(
                &name("ns1.zoneimage.test."),
                RecordType::A,
                vec![vec![192, 0, 2, 53]],
            ),
            rrset(
                &name("www.zoneimage.test."),
                RecordType::A,
                vec![vec![192, 0, 2, 80]],
            ),
            rrset(
                &name("www.zoneimage.test."),
                RecordType::Aaaa,
                vec![vec![
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80,
                ]],
            ),
            rrset(
                &name("alias.zoneimage.test."),
                RecordType::Cname,
                vec![name_wire("www.zoneimage.test.")],
            ),
            rrset(
                &name("mail.zoneimage.test."),
                RecordType::Mx,
                vec![mx_rdata(10, "mx1.zoneimage.test.")],
            ),
            rrset(
                &name("mx1.zoneimage.test."),
                RecordType::A,
                vec![vec![192, 0, 2, 25]],
            ),
            rrset(
                &name("txt.zoneimage.test."),
                RecordType::Txt,
                vec![txt_rdata(b"zone-image composer fuzz")],
            ),
            rrset(
                &name("*.wild.zoneimage.test."),
                RecordType::A,
                vec![vec![192, 0, 2, 90]],
            ),
            rrset(
                &name("tree.zoneimage.test."),
                RecordType::Dname,
                vec![name_wire("target.zoneimage.test.")],
            ),
            rrset(
                &name("leaf.target.zoneimage.test."),
                RecordType::A,
                vec![vec![192, 0, 2, 91]],
            ),
            rrset(
                &name("child.zoneimage.test."),
                RecordType::Ns,
                vec![name_wire("ns.child.zoneimage.test.")],
            ),
            rrset(
                &name("ns.child.zoneimage.test."),
                RecordType::A,
                vec![vec![192, 0, 2, 92]],
            ),
            rrset(
                &name("_sip._udp.zoneimage.test."),
                RecordType::Srv,
                vec![srv_rdata(10, 20, 5060, "sip.zoneimage.test.")],
            ),
            rrset(
                &name("sip.zoneimage.test."),
                RecordType::A,
                vec![vec![192, 0, 2, 93]],
            ),
            rrset(
                &name("bulk.zoneimage.test."),
                RecordType::Txt,
                (0..32)
                    .map(|index| txt_rdata(format!("bulk record {index:02} payload").as_bytes()))
                    .collect(),
            ),
            rrset(
                &name("www.zoneimage.test."),
                RecordType::Rrsig,
                vec![rrsig_rdata(RecordType::A)],
            ),
            rrset(
                &apex,
                RecordType::Nsec,
                vec![nsec_rdata("a.zoneimage.test.")],
            ),
            rrset(
                &apex,
                RecordType::Rrsig,
                vec![rrsig_rdata(RecordType::Nsec)],
            ),
            rrset(
                &name("a.zoneimage.test."),
                RecordType::Nsec,
                vec![nsec_rdata("m.zoneimage.test.")],
            ),
            rrset(
                &name("a.zoneimage.test."),
                RecordType::Rrsig,
                vec![rrsig_rdata(RecordType::Nsec)],
            ),
            rrset(
                &name("m.zoneimage.test."),
                RecordType::Nsec,
                vec![nsec_rdata("z.zoneimage.test.")],
            ),
            rrset(
                &name("m.zoneimage.test."),
                RecordType::Rrsig,
                vec![rrsig_rdata(RecordType::Nsec)],
            ),
            rrset(
                &name("z.zoneimage.test."),
                RecordType::Nsec,
                vec![nsec_rdata("zoneimage.test.")],
            ),
            rrset(
                &name("z.zoneimage.test."),
                RecordType::Rrsig,
                vec![rrsig_rdata(RecordType::Nsec)],
            ),
            rrset(
                &name("badns.zoneimage.test."),
                RecordType::Ns,
                vec![vec![0xc0, 0x0c]],
            ),
            rrset(
                &name("badcname.zoneimage.test."),
                RecordType::Cname,
                vec![vec![0xc0, 0x0c]],
            ),
            rrset(
                &name("badmx.zoneimage.test."),
                RecordType::Mx,
                vec![vec![0, 10, 0xc0, 0x0c]],
            ),
            Rrset::new(
                name("opaque.zoneimage.test."),
                65_280,
                QCLASS_IN,
                300,
                vec![vec![0xc0, 0x0c, 0x03, b'w', b'w']],
            ),
        ],
    )
}

fn nsec3_zone_snapshot(apex: DomainName) -> ZoneSnapshot {
    let hashes = [[0x10; 20], [0x80; 20], [0xf0; 20]];
    let owners = hashes.map(|hash| {
        name(&format!(
            "{}.nsec3.test.",
            base32hex_no_padding_lower(&hash)
        ))
    });
    let mut rrsets = vec![
        rrset(
            &apex,
            RecordType::Soa,
            vec![soa_rdata_for("nsec3.test.", 2)],
        ),
        rrset(&apex, RecordType::Ns, vec![name_wire("ns1.nsec3.test.")]),
        rrset(
            &name("ns1.nsec3.test."),
            RecordType::A,
            vec![vec![192, 0, 2, 54]],
        ),
    ];
    for index in 0..hashes.len() {
        rrsets.push(rrset(
            &owners[index],
            RecordType::Nsec3,
            vec![nsec3_rdata(&hashes[(index + 1) % hashes.len()])],
        ));
        rrsets.push(rrset(
            &owners[index],
            RecordType::Rrsig,
            vec![rrsig_rdata_for(RecordType::Nsec3, "nsec3.test.")],
        ));
    }
    ZoneSnapshot::active(apex, Some(2), rrsets)
}

fn rrset(owner: &DomainName, rr_type: RecordType, rdatas: Vec<Vec<u8>>) -> Rrset {
    Rrset::new(owner.clone(), rr_type as u16, QCLASS_IN, 300, rdatas)
}

fn answer_options(data: &[u8]) -> AnswerOptions<'_> {
    let transport = if byte(data, 0) & 1 == 0 {
        Transport::Udp
    } else {
        Transport::Tcp
    };
    let padding_block = match byte(data, 1) & 0x03 {
        0 => 0,
        1 => 8,
        2 => 32,
        _ => 128,
    };

    let mut options =
        AnswerOptions::udp(512 + (get_u16(data, 2) % (DEFAULT_MAX_UDP_PAYLOAD - 511)));
    options.transport = transport;
    options.edns_padding_block_size = padding_block;
    // Production configuration rejects zero; keep the semantic oracle inside
    // the supported 1..=8 chain-limit domain.
    options.max_cname_chain = usize::from(byte(data, 26) % 8) + 1;
    options.any_response = if byte(data, 27) & 1 == 0 {
        AnyResponseMode::Minimal
    } else {
        AnyResponseMode::Full
    };
    options
}

fn shaped_query_packet(data: &[u8]) -> Vec<u8> {
    let names = [
        "zoneimage.test.",
        "www.zoneimage.test.",
        "alias.zoneimage.test.",
        "mail.zoneimage.test.",
        "txt.zoneimage.test.",
        "badns.zoneimage.test.",
        "badcname.zoneimage.test.",
        "badmx.zoneimage.test.",
        "opaque.zoneimage.test.",
        "host.wild.zoneimage.test.",
        "leaf.tree.zoneimage.test.",
        "child.zoneimage.test.",
        "www.child.zoneimage.test.",
        "_sip._udp.zoneimage.test.",
        "absent.zoneimage.test.",
        "bulk.zoneimage.test.",
        "*.zoneimage.test.",
        "absent.nsec3.test.",
        "deep.absent.nsec3.test.",
    ];
    let qtypes = [
        RecordType::A as u16,
        RecordType::Aaaa as u16,
        RecordType::Ns as u16,
        RecordType::Cname as u16,
        RecordType::Dname as u16,
        RecordType::Soa as u16,
        RecordType::Mx as u16,
        RecordType::Srv as u16,
        RecordType::Txt as u16,
        RecordType::Ds as u16,
        RecordType::Nsec as u16,
        255,
        65_280,
        65_280 + (get_u16(data, 6) % 255),
    ];

    let qname = names[(byte(data, 4) as usize) % names.len()];
    let qtype = qtypes[(byte(data, 5) as usize) % qtypes.len()];
    let qclass = if byte(data, 8) & 0x80 == 0 {
        QCLASS_IN
    } else {
        get_u16(data, 9)
    };

    let mut packet = Vec::new();
    packet.extend_from_slice(&(QID ^ get_u16(data, 11)).to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    let include_opt = byte(data, 13) & 1 != 0;
    packet.extend_from_slice(&(include_opt as u16).to_be_bytes());
    packet.extend_from_slice(&name_wire(qname));
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&qclass.to_be_bytes());

    if include_opt {
        append_opt(&mut packet, data);
    }

    packet
}

fn append_opt(packet: &mut Vec<u8>, data: &[u8]) {
    packet.push(0);
    packet.extend_from_slice(&(RecordType::Opt as u16).to_be_bytes());
    let payload = 512 + (get_u16(data, 14) % 1232);
    packet.extend_from_slice(&payload.to_be_bytes());
    let ttl = if byte(data, 16) & 1 == 0 {
        0
    } else {
        0x8000u32
    };
    packet.extend_from_slice(&ttl.to_be_bytes());

    let option_len = byte(data, 20).min(32) as usize;
    let mut rdata = Vec::new();
    if option_len > 0 {
        rdata.extend_from_slice(&get_u16(data, 21).to_be_bytes());
        rdata.extend_from_slice(&(option_len as u16).to_be_bytes());
        for index in 0..option_len {
            rdata.push(byte(data, 23 + index));
        }
    }
    packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    packet.extend_from_slice(&rdata);
}

fn soa_rdata(serial: u32) -> Vec<u8> {
    soa_rdata_for("zoneimage.test.", serial)
}

fn soa_rdata_for(origin: &str, serial: u32) -> Vec<u8> {
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&name_wire(&format!("ns1.{origin}")));
    rdata.extend_from_slice(&name_wire(&format!("hostmaster.{origin}")));
    rdata.extend_from_slice(&serial.to_be_bytes());
    rdata.extend_from_slice(&3600u32.to_be_bytes());
    rdata.extend_from_slice(&600u32.to_be_bytes());
    rdata.extend_from_slice(&86400u32.to_be_bytes());
    rdata.extend_from_slice(&300u32.to_be_bytes());
    rdata
}

fn mx_rdata(preference: u16, exchange: &str) -> Vec<u8> {
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&preference.to_be_bytes());
    rdata.extend_from_slice(&name_wire(exchange));
    rdata
}

fn srv_rdata(priority: u16, weight: u16, port: u16, target: &str) -> Vec<u8> {
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&priority.to_be_bytes());
    rdata.extend_from_slice(&weight.to_be_bytes());
    rdata.extend_from_slice(&port.to_be_bytes());
    rdata.extend_from_slice(&name_wire(target));
    rdata
}

fn txt_rdata(text: &[u8]) -> Vec<u8> {
    let mut rdata = Vec::new();
    rdata.push(text.len().min(255) as u8);
    rdata.extend_from_slice(&text[..text.len().min(255)]);
    rdata
}

fn rrsig_rdata(type_covered: RecordType) -> Vec<u8> {
    rrsig_rdata_for(type_covered, "zoneimage.test.")
}

fn rrsig_rdata_for(type_covered: RecordType, signer: &str) -> Vec<u8> {
    let mut rdata = (type_covered as u16).to_be_bytes().to_vec();
    rdata.extend_from_slice(&[8, 2]);
    rdata.extend_from_slice(&300u32.to_be_bytes());
    rdata.extend_from_slice(&1_700_086_400u32.to_be_bytes());
    rdata.extend_from_slice(&1_700_000_000u32.to_be_bytes());
    rdata.extend_from_slice(&1u16.to_be_bytes());
    rdata.extend_from_slice(&name_wire(signer));
    rdata.extend_from_slice(b"signature");
    rdata
}

fn nsec_rdata(next_owner: &str) -> Vec<u8> {
    let mut rdata = name_wire(next_owner);
    rdata.extend_from_slice(&[0, 1, 0x40]);
    rdata
}

fn nsec3_rdata(next_hash: &[u8]) -> Vec<u8> {
    let mut rdata = vec![1, 0];
    rdata.extend_from_slice(&0u16.to_be_bytes());
    rdata.push(0);
    rdata.push(next_hash.len() as u8);
    rdata.extend_from_slice(next_hash);
    rdata.extend_from_slice(&[0, 1, 0x40]);
    rdata
}

fn base32hex_no_padding_lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
    let mut output = String::new();
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    for byte in bytes {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(ALPHABET[((accumulator >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits != 0 {
        output.push(ALPHABET[((accumulator << (5 - bits)) & 0x1f) as usize] as char);
    }
    output
}

fn name(value: &str) -> DomainName {
    DomainName::from_absolute_str(value).expect("static name is valid")
}

fn name_wire(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn byte(data: &[u8], index: usize) -> u8 {
    data.get(index).copied().unwrap_or(0)
}

fn get_u16(data: &[u8], index: usize) -> u16 {
    u16::from_be_bytes([byte(data, index), byte(data, index + 1)])
}
