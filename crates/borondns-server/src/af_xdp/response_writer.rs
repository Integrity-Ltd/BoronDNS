use super::*;

/// A payload prepared in a live receive frame, never an owned DNS byte vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreparedReply {
    pub(super) frame_index: usize,
    pub(super) len: usize,
    pub(super) epoch: u64,
    pub(crate) send_category: Option<crate::QueryLatencyCategory>,
}

#[cfg(test)]
impl PreparedReply {
    pub(crate) fn for_test(
        frame_index: usize,
        len: usize,
        send_category: Option<crate::QueryLatencyCategory>,
    ) -> Self {
        Self {
            frame_index,
            len,
            epoch: 0,
            send_category,
        }
    }
    pub(crate) fn test_location(self) -> (usize, usize) {
        (self.frame_index, self.len)
    }
}

pub(super) struct ReplyFrames<'a> {
    pub(super) frames: &'a mut [Option<ReceivedFrame>],
}

impl crate::udp::UdpReplyBuffers for ReplyFrames<'_> {
    fn buffer(&mut self, frame_index: usize) -> Option<&mut [u8]> {
        let frame = self.frames.get_mut(frame_index)?.as_mut()?;
        frame.prepared_len = None;
        let start = frame.frame.payload().start;
        let end = frame.packet.capacity();
        let delta = i32::try_from(end.checked_sub(frame.packet.len())?).ok()?;
        frame.packet.adjust_tail(delta).ok()?;
        frame.packet.get_mut(start..end)
    }

    fn seal(
        &mut self,
        frame_index: usize,
        len: usize,
        send_category: Option<crate::QueryLatencyCategory>,
    ) -> Option<PreparedReply> {
        let frame = self.frames.get_mut(frame_index)?.as_mut()?;
        if len < 12
            || len
                > frame
                    .packet
                    .len()
                    .checked_sub(frame.frame.payload().start)?
        {
            return None;
        }
        frame.prepared_len = Some(len);
        Some(PreparedReply {
            frame_index,
            len,
            epoch: frame.reply_epoch,
            send_category,
        })
    }
}

pub(super) fn finish(
    frame: &mut ReceivedFrame,
    index: usize,
    reply: PreparedReply,
) -> Result<usize, AfXdpFrameError> {
    if reply.frame_index != index
        || reply.epoch != frame.reply_epoch
        || frame.prepared_len.take() != Some(reply.len)
    {
        return Err(AfXdpFrameError::PacketResize);
    }
    let frame_len = frame
        .frame
        .payload()
        .start
        .checked_add(reply.len)
        .ok_or(AfXdpFrameError::ResponseTooLarge)?;
    let delta = i32::try_from(frame_len)
        .and_then(|n| i32::try_from(frame.packet.len()).map(|old| n - old))
        .map_err(|_| AfXdpFrameError::PacketResize)?;
    frame
        .packet
        .adjust_tail(delta)
        .map_err(|_| AfXdpFrameError::PacketResize)?;
    match frame.frame.clone() {
        UdpIpFrame::Ipv4(parsed) => {
            rewrite_udp_ipv4_response_headers(&mut frame.packet, parsed, reply.len)
        }
        UdpIpFrame::Ipv6(parsed) => {
            rewrite_udp_ipv6_response_headers(&mut frame.packet, parsed, reply.len)
        }
    }
}
