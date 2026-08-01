    #[test]
    fn wire_name_helpers_reject_malformed_names_without_panicking() {
        let invalid_standalone_names: &[&[u8]] = &[
            b"",
            b"\xc0\x0c",
            b"\x40aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x00",
            b"\x03ww",
        ];

        for wire_name in invalid_standalone_names {
            assert_eq!(wire_label_offsets(wire_name), None, "{wire_name:02x?}");
            assert_eq!(wire_name_len_at(wire_name, 0), None, "{wire_name:02x?}");
        }

        assert_eq!(
            wire_label_offsets(b"\x03www\x07example\x04test\x00")
                .unwrap()
                .as_slice(),
            &[0, 4, 12]
        );
        assert_eq!(wire_label_offsets(b"\x03www\x00extra"), None);
        assert_eq!(wire_name_len_at(b"\x03www\x00extra", 0), Some(5));
        assert_eq!(wire_name_len_at(b"\x00\x03www\x00", 1), Some(5));
    }

    #[test]
    fn domain_name_display_escapes_non_printable_label_octets() {
        let (name, consumed) = DomainName::parse(b"\x05a\x1b\x00\\.\x01b\x00", 0).unwrap();

        assert_eq!(consumed, 9);
        assert_eq!(name.to_string(), "a\\027\\000\\092\\046.b.");
    }

    #[test]
    fn domain_name_replaces_borrowed_wire_suffix_without_parsing_domain() {
        let qname = DomainName::from_absolute_str("leaf.subtree.example.test.").unwrap();
        let suffix_wire = DomainName::from_absolute_str("subtree.example.test.")
            .unwrap()
            .to_wire();
        let replacement = DomainName::from_absolute_str("target.example.test.").unwrap();
        let expected = DomainName::from_absolute_str("leaf.target.example.test.").unwrap();

        assert_eq!(
            qname.with_replaced_wire_suffix(&suffix_wire, &replacement),
            Some(expected.clone())
        );
        assert_eq!(
            qname.with_replaced_wire_suffix_and_wire(&suffix_wire, &replacement),
            Some((expected.clone(), expected.to_wire()))
        );
        let replacement_wire = replacement.to_wire();
        let suffix_label_count = wire_label_count(&suffix_wire).expect("suffix wire is valid");
        let (wire_only, prefix_len) = qname
            .with_replaced_wire_suffix_wire_counted(
                &suffix_wire,
                suffix_label_count,
                &replacement_wire,
            )
            .expect("suffix replacement writes target wire");
        assert_eq!(wire_only.as_slice(), expected.to_wire().as_slice());
        assert_eq!(prefix_len, 1);

        let mixed_case = DomainName::from_absolute_str("SubTree.Example.TEST.")
            .unwrap()
            .to_wire();
        assert_eq!(
            qname.with_replaced_wire_suffix(&mixed_case, &replacement),
            Some(expected.clone())
        );
        assert_eq!(
            qname.with_replaced_wire_suffix_and_wire(&mixed_case, &replacement),
            Some((expected.clone(), expected.to_wire()))
        );
    }

    #[test]
    fn domain_name_rejects_malformed_wire_suffix_replacement() {
        let qname = DomainName::from_absolute_str("leaf.subtree.example.test.").unwrap();
        let replacement = DomainName::from_absolute_str("target.example.test.").unwrap();

        assert_eq!(
            qname.with_replaced_wire_suffix(b"\x03bad\x00extra", &replacement),
            None
        );
        assert_eq!(
            qname.with_replaced_wire_suffix(b"\xc0\x0c", &replacement),
            None
        );
        assert_eq!(
            qname.with_replaced_wire_suffix(
                &DomainName::from_absolute_str("other.example.test.")
                    .unwrap()
                    .to_wire(),
                &replacement,
            ),
            None
        );
    }

    #[test]
    fn domain_name_canonical_wire_lowercases_labels_without_reparse() {
        let name = DomainName::from_absolute_str("WWW.Example.TEST.").unwrap();

        assert_eq!(
            name.to_canonical_wire(),
            DomainName::from_absolute_str("www.example.test.")
                .unwrap()
                .to_wire()
        );
    }

    #[test]
    fn domain_name_canonical_key_preserves_wire_label_boundaries() {
        let (embedded_dot, consumed) =
            DomainName::parse(b"\x03a.b\x07example\x04test\x00", 0).unwrap();
        let split_labels = DomainName::from_absolute_str("a.b.example.test.").unwrap();

        assert_eq!(consumed, 18);
        assert_ne!(embedded_dot, split_labels);
        assert_ne!(embedded_dot.canonical_key(), split_labels.canonical_key());
    }

    #[test]
    fn domain_name_canonical_key_is_case_folded_and_octet_unambiguous() {
        let root = DomainName::root();
        let mixed_case = DomainName::from_absolute_str("WWW.Example.TEST.").unwrap();
        let lowercase = DomainName::from_absolute_str("www.example.test.").unwrap();
        let (escaped_octets, _) =
            DomainName::parse(b"\x05.\\\x00\x7f\xff\x00", 0).unwrap();
        let (literal_escape_text, _) =
            DomainName::parse(b"\x0d\\046\\092\\000x\x00", 0).unwrap();

        assert_eq!(root.canonical_key(), ".");
        assert_eq!(mixed_case.canonical_key(), lowercase.canonical_key());
        assert_eq!(escaped_octets.canonical_key(), "\\046\\092\\000\\127\\255.");
        assert_ne!(escaped_octets.canonical_key(), literal_escape_text.canonical_key());

        let mut keys = std::collections::HashSet::new();
        for byte in 0u8..=u8::MAX {
            let wire = [1, byte, 0];
            let (name, consumed) = DomainName::parse(&wire, 0).unwrap();
            assert_eq!(consumed, wire.len());
            keys.insert(name.canonical_key());
        }
        assert_eq!(keys.len(), 230, "only ASCII case pairs compare equal");
    }

    #[test]
    fn domain_name_canonical_key_handles_maximum_length_name() {
        let mut mixed_wire = Vec::new();
        let mut lower_wire = Vec::new();
        for (len, mixed, lower) in [
            (63, b'A', b'a'),
            (63, b'B', b'b'),
            (63, b'C', b'c'),
            (61, b'D', b'd'),
        ] {
            mixed_wire.push(len);
            mixed_wire.extend(std::iter::repeat_n(mixed, usize::from(len)));
            lower_wire.push(len);
            lower_wire.extend(std::iter::repeat_n(lower, usize::from(len)));
        }
        mixed_wire.push(0);
        lower_wire.push(0);

        assert_eq!(mixed_wire.len(), 255);
        let (mixed, mixed_consumed) = DomainName::parse(&mixed_wire, 0).unwrap();
        let (lower, lower_consumed) = DomainName::parse(&lower_wire, 0).unwrap();
        assert_eq!(mixed_consumed, 255);
        assert_eq!(lower_consumed, 255);
        assert_eq!(mixed.canonical_key(), lower.canonical_key());
    }

    #[test]
    fn zone_snapshot_keeps_colliding_presentation_names_distinct() {
        let (embedded_dot, _) =
            DomainName::parse(b"\x03a.b\x07example\x04test\x00", 0).unwrap();
        let split_labels = DomainName::from_absolute_str("a.b.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    embedded_dot.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 1]],
                ),
                Rrset::new(
                    split_labels.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 2]],
                ),
            ],
        );

        assert_eq!(
            snapshot
                .offline_oracle()
                .lookup(&embedded_dot, RecordType::A as u16, 1)
                .answers[0]
                .rdata,
            vec![192, 0, 2, 1]
        );
        assert_eq!(
            snapshot
                .offline_oracle()
                .lookup(&split_labels, RecordType::A as u16, 1)
                .answers[0]
                .rdata,
            vec![192, 0, 2, 2]
        );
    }

    #[test]
    fn domain_name_wire_len_matches_serialized_wire() {
        let name = DomainName::from_absolute_str("WWW.Example.TEST.").unwrap();
        let mut wire = Vec::with_capacity(name.wire_len());

        name.append_wire_to(&mut wire);

        assert_eq!(name.wire_len(), wire.len());
        assert_eq!(wire, name.to_wire());
    }

    #[test]
    fn domain_name_suffix_from_label_index_clones_checked_suffix() {
        let name = DomainName::from_absolute_str("leaf.subtree.example.test.").unwrap();

        assert_eq!(
            name.suffix_from_label_index(1),
            Some(DomainName::from_absolute_str("subtree.example.test.").unwrap())
        );
        assert_eq!(
            name.suffix_from_label_index(3),
            Some(DomainName::from_absolute_str("test.").unwrap())
        );
        assert_eq!(name.suffix_from_label_index(4), Some(DomainName::root()));
        assert_eq!(name.suffix_from_label_index(5), None);
    }

    #[test]
    fn wire_suffix_keys_borrow_canonical_lowercase_suffixes() {
        let lowercase = b"\x03www\x07example\x04test\x00";
        let mixed_case = b"\x03WWW\x07Example\x04test\x00";

        assert!(matches!(
            canonical_wire_suffix_key(lowercase),
            std::borrow::Cow::Borrowed(_)
        ));
        assert!(matches!(
            canonical_wire_suffix_key(mixed_case),
            std::borrow::Cow::Owned(_)
        ));
        assert_eq!(wire_suffix_key(lowercase), wire_suffix_key(mixed_case));
        assert_eq!(wire_suffix_small_key(lowercase).as_slice(), lowercase);
        assert_eq!(
            wire_suffix_small_key(mixed_case).as_slice(),
            wire_suffix_key(mixed_case).as_slice()
        );
        let lowercase_labels = vec![b"www".to_vec(), b"example".to_vec(), b"test".to_vec()];
        let mixed_case_labels = vec![b"WWW".to_vec(), b"Example".to_vec(), b"test".to_vec()];
        assert_eq!(
            label_suffix_small_key(&lowercase_labels, lowercase.len(), true).as_slice(),
            lowercase
        );
        assert_eq!(
            label_suffix_small_key(&mixed_case_labels, mixed_case.len(), false).as_slice(),
            wire_suffix_key(mixed_case).as_slice()
        );
        assert!(wire_suffix_matches_key(
            mixed_case,
            wire_suffix_small_key(lowercase).as_slice()
        ));
        assert!(wire_suffix_matches_key(
            lowercase,
            wire_suffix_small_key(lowercase).as_slice()
        ));
        assert!(wire_label_matches_key(b"example", b"example"));
        assert!(wire_label_matches_key(b"Example", b"example"));
        assert!(!wire_label_matches_key(b"example", b"invalid"));
    }

    #[test]
    fn wire_name_compressor_copies_malformed_names_opaquely() {
        let mut compressor = WireNameCompressor::default();
        compressor.register_wire_name_at_offset(b"\x07example\x04test\x00", 12);
        assert_eq!(compressor.suffix_offsets.len(), 2);
        assert!(
            !compressor.suffix_offsets.spilled(),
            "common response suffix table remains inline"
        );

        for wire_name in [
            b"\xc0\x0c".as_slice(),
            b"\x03ww".as_slice(),
            b"\x03www\x00extra".as_slice(),
        ] {
            let mut out = Vec::new();
            compressor.write_wire_name(wire_name, &mut out);
            assert_eq!(out, wire_name);
        }
    }

    #[test]
    fn wire_name_compressor_skips_offsets_after_selected_pointer() {
        let mut compressor = WireNameCompressor::default();
        compressor.register_wire_name_at_offset(b"\x07example\x04test\x00", 12);

        let (write_end, pointer_suffix) = compressor
            .wire_name_write_plan(b"\x03www\x07example\x04test\x00", true)
            .unwrap();
        assert_eq!(write_end, 4);
        assert_eq!(pointer_suffix, Some((4, 12)));

        let (write_end, pointer_suffix) = compressor
            .wire_name_write_plan(b"\x07example\x04test\x00", true)
            .unwrap();
        assert_eq!(write_end, 0);
        assert_eq!(pointer_suffix, Some((0, 12)));
    }

    #[test]
    fn wire_name_compressor_skips_duplicate_full_suffix_probe_after_miss() {
        let mut compressor = WireNameCompressor::default();
        compressor.register_wire_name_at_offset(b"\x07example\x04test\x00", 12);

        let (write_end, pointer_suffix) = compressor
            .wire_name_write_plan(b"\x03www\x07example\x04test\x00", false)
            .unwrap();
        assert_eq!(write_end, 4);
        assert_eq!(pointer_suffix, Some((4, 12)));

        let (write_end, pointer_suffix) = compressor
            .wire_name_write_plan(b"\x07example\x04test\x00", false)
            .unwrap();
        assert_eq!(write_end, 8);
        assert_eq!(pointer_suffix, Some((8, 20)));
    }

    #[test]
    fn wire_name_compressor_registers_prechecked_suffixes_once() {
        let mut compressor = WireNameCompressor::default();
        compressor.register_wire_name_at_offset(b"\x07example\x04test\x00", 12);

        let mut exact = Vec::new();
        compressor.write_wire_name(b"\x07example\x04test\x00", &mut exact);
        assert_eq!(
            exact, b"\xc0\x0c",
            "exact full-name suffix emits the existing pointer immediately"
        );
        assert_eq!(
            compressor.suffix_offsets.len(),
            2,
            "exact suffix pointer does not register duplicate suffixes"
        );

        let mut out = vec![0; 40];
        compressor.write_wire_name(b"\x03www\x07example\x04test\x00", &mut out);
        assert_eq!(
            &out[40..],
            b"\x03www\xc0\x0c",
            "existing suffix is compressed"
        );
        assert_eq!(
            compressor.suffix_offsets.len(),
            3,
            "only the missing pre-pointer suffix is registered"
        );

        out.resize(80, 0);
        compressor.write_wire_name(b"\x03WWW\x07example\x04test\x00", &mut out);
        assert_eq!(
            &out[80..],
            b"\xc0\x28",
            "case-insensitive full-name suffix reuses the first registration"
        );
        assert_eq!(compressor.suffix_offsets.len(), 3);
    }

    #[test]
    fn zone_image_known_name_rdata_encoder_compresses_or_copies_safely() {
        let mut compressor = WireNameCompressor::default();
        compressor.register_wire_name_at_offset(b"\x07example\x04test\x00", 12);

        let mut single_name = Vec::new();
        encode_zone_image_wire_record_rdata(
            PackedRdataEncoding::single_name(),
            b"\x06target\x07example\x04test\x00",
            &mut single_name,
            &mut compressor,
        );
        assert_eq!(single_name, b"\x06target\xc0\x0c");

        let mut mx = Vec::new();
        encode_zone_image_wire_record_rdata(
            PackedRdataEncoding::mx(),
            b"\x00\x0a\x04mail\x07example\x04test\x00",
            &mut mx,
            &mut compressor,
        );
        assert_eq!(mx, b"\x00\x0a\x04mail\xc0\x0c");

        let mut soa = Vec::new();
        let mut soa_rdata =
            b"\x02ns\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00".to_vec();
        soa_rdata.extend_from_slice(&[0; 20]);
        encode_zone_image_wire_record_rdata(
            PackedRdataEncoding::soa(17, 25),
            &soa_rdata,
            &mut soa,
            &mut compressor,
        );
        let mut expected_soa = b"\x02ns\xc0\x0c\x0ahostmaster\xc0\x0c".to_vec();
        expected_soa.extend_from_slice(&[0; 20]);
        assert_eq!(soa, expected_soa);

        for malformed in [
            b"\xc0\x0c".as_slice(),
            b"\x03ww".as_slice(),
            b"\x00\x0a\x03ww".as_slice(),
            b"\x02ns\x00\x04host\x00short".as_slice(),
        ] {
            let mut out = Vec::new();
            encode_zone_image_wire_record_rdata(
                PackedRdataEncoding::copy(),
                malformed,
                &mut out,
                &mut compressor,
            );
            assert_eq!(out, malformed, "copy RDATA changed");
        }

        let mut copy_record = Vec::new();
        encode_zone_image_wire_record(
            ZoneImageWireRecord {
                owner_wire: b"\x00",
                fixed_fields: zone_image_record_fixed_fields(RecordType::Txt as u16, 1, 300),
                rdlength_bytes: 3u16.to_be_bytes(),
                rdata_encoding: PackedRdataEncoding::copy(),
                rdata: b"\x02ok",
            },
            &mut copy_record,
            &mut WireNameCompressor::default(),
        );
        assert_eq!(&copy_record[9..11], &3u16.to_be_bytes());
        assert_eq!(&copy_record[11..], b"\x02ok");
    }
