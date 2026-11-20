use super::*;
use gent_crypto::NodeIdentity;

fn canonical_batch() -> Batch {
    let writer = NodeIdentity::generate().unwrap();
    let mut batch = Batch::default();
    let mut previous = [0; 32];
    for n in 0..3 {
        let packet = writer
            .sign_stream_packet(b"abc", n, previous, &[0xba; 1024])
            .unwrap();
        previous = packet.digest().unwrap();
        assert!(batch.push(packet.encode().unwrap()).unwrap());
    }
    batch
}

#[test]
fn compact_session_preserves_every_canonical_packet() {
    let batch = canonical_batch();
    let frame = encode(b"abc", &batch).unwrap();
    assert!(frame.len() < batch.encode().len());
    assert_eq!(&frame[..10], b"GNTS\x02\x00\x03abc");
    let (group, packets) = decode(&frame).unwrap();
    assert_eq!(group, b"abc");
    let canonical: Vec<_> = packets.iter().map(|p| p.encode().unwrap()).collect();
    assert_eq!(canonical, batch.packets());
}

#[test]
fn rejects_malformed_or_misrouted_requests_before_delivery() {
    let batch = canonical_batch();
    assert!(encode(b"", &batch).is_err());
    assert!(encode(b"abc", &Batch::default()).is_err());
    assert!(decode(&encode(b"other", &batch).unwrap()).is_err());
    let mut frame = encode(b"abc", &batch).unwrap();
    for index in [0, 4, 5, 6, 10, 14, 15, 16] {
        frame[index] ^= 0xff;
        assert!(decode(&frame).is_err());
        frame[index] ^= 0xff;
    }
    for len in [0, 4, 5, 6, 7, 9, 10, frame.len() - 1] {
        assert!(decode(&frame[..len]).is_err());
    }
    frame.push(0);
    assert!(decode(&frame).is_err());
    assert!(request_group(&vec![0; MAX_FRAME_BYTES + 1]).is_err());

    let mut reordered = Batch::default();
    for index in [0, 2, 1] {
        assert!(reordered.push(batch.packets()[index].clone()).unwrap());
    }
    assert!(decode(&encode(b"abc", &reordered).unwrap()).is_err());
}
