use super::*;
use crate::zone_image::ZoneImageDirectRrset;

pub const DNS_SERVING_BATCH_SIZE: usize = 8;

#[cfg(all(test, feature = "experimental-query-preparation"))]
thread_local! {
    pub(super) static FALLBACK_PREPARATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// A packet-bound query prepared within a bounded serving batch.
#[derive(Clone, Copy)]
pub struct PreparedDnsBatchQuery<'a, 'packet> {
    request: &'a ParsedDnsRequest<'packet>,
    zones: &'a ZoneStore,
    pub(super) lookup: Option<BatchLookup<'a>>,
    #[cfg(feature = "experimental-fused-serving")]
    pub(super) selector: &'a crate::zone::BatchZoneSelector<'a>,
    #[cfg(feature = "experimental-fused-serving")]
    pub(super) default_provider: bool,
}

#[derive(Clone, Copy)]
pub(super) struct BatchLookup<'a> {
    pub(super) zone: Option<crate::zone::PublishedZoneRef<'a>>,
    pub(super) selected: Option<crate::zone::SelectedZoneQuery<'a>>,
    compact: Option<Option<ZoneImageDirectRrset<'a>>>,
    #[cfg(feature = "experimental-fused-serving")]
    pub(super) fused: Option<ZoneImageDirectRrset<'a>>,
}

pub fn with_prepared_dns_batch<R>(
    requests: &[ParsedDnsRequest<'_>],
    zones: &ZoneStore,
    visit: impl FnOnce(&[PreparedDnsBatchQuery<'_, '_>]) -> R,
) -> R {
    assert!(requests.len() <= DNS_SERVING_BATCH_SIZE);
    zones.with_batch_selector(|selector| {
        // Each phase completes for the bounded group before the next starts.
        // All policy decisions and response construction still run through the
        // reference answer path; these are only packet-bound lookup results.
        let candidates: SmallVec<[_; DNS_SERVING_BATCH_SIZE]> = requests
            .iter()
            .map(|r| {
                let h = r.header()?;
                if h.is_response() || h.opcode() != Some(Opcode::Query) {
                    return None;
                }
                let q = r.question()?;
                let metadata = r.metadata().ok()?;
                if q.qclass != DNS_CLASS_IN || rejected_qtype(q.qtype).is_some() {
                    return None;
                }
                Some((q, metadata.dnssec_requested()))
            })
            .collect();
        #[cfg(feature = "experimental-fused-serving")]
        let fused = {
            let queries: SmallVec<[_; DNS_SERVING_BATCH_SIZE]> = candidates
                .iter()
                .map(|candidate| {
                    let (q, dnssec) = candidate.as_ref()?;
                    if *dnssec {
                        return None;
                    }
                    Some((&q.qname, q.qtype, q.qname_ascii_lowercase()))
                })
                .collect();
            selector.select_fused_many(&queries)
        };
        #[cfg(feature = "experimental-query-preparation")]
        if !requests.is_empty() && fused.iter().all(Option::is_some) {
            // Keep the pinned selector for custom providers and sizing/policy
            // fallback, but do not build selection/index/first-entry vectors
            // for requests whose exact answers are already publication-proven.
            let batch: SmallVec<[_; DNS_SERVING_BATCH_SIZE]> = requests
                .iter()
                .zip(&fused)
                .map(|(request, &fused)| PreparedDnsBatchQuery {
                    request,
                    zones,
                    lookup: Some(BatchLookup {
                        zone: None,
                        selected: None,
                        compact: None,
                        fused,
                    }),
                    selector: &selector,
                    default_provider: false,
                })
                .collect();
            return visit(&batch);
        }
        #[cfg(all(test, feature = "experimental-query-preparation"))]
        FALLBACK_PREPARATIONS.with(|count| count.set(count.get() + 1));
        #[cfg(not(feature = "experimental-batch-authority"))]
        let selections: SmallVec<[_; DNS_SERVING_BATCH_SIZE]> = candidates
            .iter()
            .map(|c| {
                c.and_then(|(q, _)| {
                    selector.select(
                        &q.qname,
                        q.qname_ascii_lowercase(),
                        q.qtype == RecordType::Ds as u16,
                    )
                })
            })
            .collect();
        #[cfg(feature = "experimental-batch-authority")]
        let selections = {
            let queries: SmallVec<[_; DNS_SERVING_BATCH_SIZE]> = candidates
                .iter()
                .enumerate()
                .map(|(_index, c)| {
                    #[cfg(feature = "experimental-fused-serving")]
                    if fused[_index].is_some() {
                        return None;
                    }
                    c.map(|(q, _)| {
                        (
                            &q.qname,
                            q.qname_ascii_lowercase(),
                            q.qtype == RecordType::Ds as u16,
                        )
                    })
                })
                .collect();
            selector.select_many(&queries)
        };
        let indexes: SmallVec<[_; DNS_SERVING_BATCH_SIZE]> = selections
            .iter()
            .zip(&candidates)
            .enumerate()
            .map(|(_index, (selection, candidate))| {
                #[cfg(feature = "experimental-fused-serving")]
                if fused[_index].is_some() {
                    return None;
                }
                let (_, selected) = selection.as_ref()?;
                let (q, dnssec) = candidate.as_ref()?;
                if *dnssec {
                    return None;
                }
                selected
                    .as_ref()?
                    .prepare_compact(q.qtype, q.qclass, q.qname_ascii_lowercase())
            })
            .collect();
        // Copy independent first cache lines without a data-dependent branch
        // on their contents. Validation happens only after the group is read.
        let first_entries: SmallVec<[_; DNS_SERVING_BATCH_SIZE]> = indexes
            .iter()
            .map(|index| {
                index
                    .as_ref()
                    .map_or_else(Default::default, |index| index.read_first())
            })
            .collect();
        let batch: SmallVec<[_; DNS_SERVING_BATCH_SIZE]> = requests
            .iter()
            .enumerate()
            .map(|(i, request)| {
                let lookup = candidates[i].map(|(_, dnssec)| {
                    let (zone, selected) =
                        selections[i].map_or((None, None), |(z, s)| (Some(z), s));
                    // A completed miss is distinct from an unprepared lookup.
                    let compact = (!dnssec && selected.is_some()).then(|| {
                        indexes[i]
                            .as_ref()
                            .and_then(|p| p.resolve(&first_entries[i]))
                    });
                    BatchLookup {
                        zone,
                        selected,
                        compact,
                        #[cfg(feature = "experimental-fused-serving")]
                        fused: fused[i],
                    }
                });
                PreparedDnsBatchQuery {
                    request,
                    zones,
                    lookup,
                    #[cfg(feature = "experimental-fused-serving")]
                    selector: &selector,
                    #[cfg(feature = "experimental-fused-serving")]
                    default_provider: false,
                }
            })
            .collect();
        visit(&batch)
    })
}

impl PreparedDnsBatchQuery<'_, '_> {
    /// Answer into a bounded caller buffer, retaining the normal owned fallback.
    #[cfg(feature = "experimental-response-writer")]
    #[allow(clippy::too_many_arguments)]
    pub fn answer_with_default_hooks_into(
        &self,
        zones: &ZoneStore,
        options: AnswerOptions,
        notify_authorized: impl Fn(&DomainName, u16) -> bool,
        notify_accepted: impl Fn(&DomainName, u16, Option<u32>) -> bool,
        lookup_observed: impl Fn(LookupMetrics),
        destination: &mut [u8],
    ) -> BufferedDatagramAction {
        if !std::ptr::eq(zones, self.zones) {
            return self
                .answer_with_default_hooks(
                    zones,
                    options,
                    notify_authorized,
                    notify_accepted,
                    lookup_observed,
                )
                .into();
        }
        let observer = LookupMetricsObserver {
            callback: lookup_observed,
        };
        let prepared = Self {
            default_provider: true,
            ..*self
        };
        answer_message_with_notify_hooks_observer_and_zone_image(
            self.request,
            zones,
            options,
            notify_authorized,
            notify_accepted,
            &observer,
            &default_zone_image_provider,
            Some(&prepared),
            Some(destination),
        )
    }

    pub(super) fn compact_for(
        &self,
        image: &ZoneImage,
    ) -> Option<Option<ZoneImageDirectRrset<'_>>> {
        let lookup = self.lookup.as_ref()?;
        if !std::ptr::eq(lookup.selected.as_ref()?.image(), image) {
            return None;
        }
        lookup.compact
    }
    pub fn request(&self) -> &ParsedDnsRequest<'_> {
        self.request
    }

    pub fn matches_packet(&self, packet: &[u8]) -> bool {
        std::ptr::eq(self.request.packet, packet)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn answer_with_hooks(
        &self,
        zones: &ZoneStore,
        options: AnswerOptions,
        notify_authorized: impl Fn(&DomainName, u16) -> bool,
        notify_accepted: impl Fn(&DomainName, u16, Option<u32>) -> bool,
        lookup_observed: impl Fn(LookupMetrics),
        provider: ZoneImageProvider<'_>,
    ) -> DatagramAction {
        self.answer_with_provider(
            zones,
            options,
            notify_authorized,
            notify_accepted,
            lookup_observed,
            provider,
            false,
        )
    }

    /// Answer using the published immutable image, with no custom image hook.
    /// This explicit entry point permits publication-built answer proofs without
    /// silently bypassing the provider supplied to `answer_with_hooks`.
    pub fn answer_with_default_hooks(
        &self,
        zones: &ZoneStore,
        options: AnswerOptions,
        notify_authorized: impl Fn(&DomainName, u16) -> bool,
        notify_accepted: impl Fn(&DomainName, u16, Option<u32>) -> bool,
        lookup_observed: impl Fn(LookupMetrics),
    ) -> DatagramAction {
        self.answer_with_provider(
            zones,
            options,
            notify_authorized,
            notify_accepted,
            lookup_observed,
            &default_zone_image_provider,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn answer_with_provider(
        &self,
        zones: &ZoneStore,
        options: AnswerOptions,
        notify_authorized: impl Fn(&DomainName, u16) -> bool,
        notify_accepted: impl Fn(&DomainName, u16, Option<u32>) -> bool,
        lookup_observed: impl Fn(LookupMetrics),
        provider: ZoneImageProvider<'_>,
        _default_provider: bool,
    ) -> DatagramAction {
        if !std::ptr::eq(zones, self.zones) {
            return self.request.answer_with_hooks(
                zones,
                options,
                notify_authorized,
                notify_accepted,
                lookup_observed,
                provider,
            );
        }
        let observer = LookupMetricsObserver {
            callback: lookup_observed,
        };
        let prepared = Self {
            #[cfg(feature = "experimental-fused-serving")]
            default_provider: _default_provider,
            ..*self
        };
        answer_message_with_notify_hooks_observer_and_zone_image(
            self.request,
            zones,
            options,
            notify_authorized,
            notify_accepted,
            &observer,
            provider,
            Some(&prepared),
            #[cfg(feature = "experimental-response-writer")]
            None,
        )
        .into_owned()
    }
}
