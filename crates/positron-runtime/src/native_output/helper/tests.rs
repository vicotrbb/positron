use super::*;

#[test]
fn closed_frames_decode_exact_payload_bounds_and_keep_following_records() {
    for length in [0, 1, RECORD_BYTES] {
        let mut bytes = u16::try_from(length).unwrap().to_be_bytes().to_vec();
        bytes.extend(std::iter::repeat_n(b'x', length));
        assert_eq!(decode_frame(&bytes), Some(length));
        let mut next = bytes.clone();
        next.extend([0, 0]);
        let mut cursor = std::io::Cursor::new(next);
        let record = read_record(&mut cursor).unwrap();
        assert_eq!(record.length, length);
        assert_eq!(record.bytes.get(..length).unwrap(), vec![b'x'; length]);
        assert_eq!(cursor.position(), u64::try_from(length + 2).unwrap());
        assert_eq!(read_record(&mut cursor).unwrap().length, 0);
    }
}

#[test]
fn oversized_incomplete_and_truncated_frames_are_refused_without_payload_allocation() {
    for bytes in [vec![], vec![0], vec![0, 1], vec![1, 255], vec![255, 255]] {
        assert_eq!(decode_frame(&bytes), None);
    }
    let mut maximum = 510_u16.to_be_bytes().to_vec();
    maximum.extend([0_u8; 509]);
    assert_eq!(decode_frame(&maximum), None);
}
