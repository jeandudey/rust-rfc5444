// The olsr.org Optimized Link-State Routing daemon version 2 (olsrd2)
// Copyright (c) 2004-2013, the olsr.org team - see HISTORY file
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in
//   the documentation and/or other materials provided with the
//   distribution.
// * Neither the name of olsr.org, olsrd nor the names of its
//   contributors may be used to endorse or promote products derived
//   from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Visit http://www.olsr.org for more information.
//
// If you find this software useful feel free to make a donation
// to the project. For more information see the website or contact
// the copyright holders.

const RESULT: &[u8] = &[
    0x00, 0x01, 0x03, 0x00, 0x28, 0x00, 0x00, 0x04, 0x80, 0x01, 0x0a, 0x01,
    0x00, 0x65, 0x01, 0x00, 0x66, 0x01, 0x00, 0x67, 0x0b, 0x0b, 0x0b, 0x00,
    0x10, 0x02, 0x50, 0x01, 0x01, 0x00, 0x03, 0x50, 0x00, 0x01, 0x01, 0x03,
    0x30, 0x02, 0x03, 0x01, 0x01,
];

#[test]
fn test_parse_nhdp() {
    let mut pkt = rfc5444::parser::packet(RESULT).unwrap();

    assert_eq!(pkt.hdr.version, 0);
    assert!(pkt.hdr.seq_num.is_none());
    assert!(pkt.hdr.tlv_block.is_none());

    let mut msg = pkt.messages.next().unwrap().unwrap();
    assert_eq!(msg.hdr.r#type, 1);
    assert_eq!(msg.hdr.address_length, 4);
    assert!(msg.hdr.orig_addr.is_none());
    assert!(msg.hdr.hop_limit.is_none());
    assert!(msg.hdr.hop_count.is_none());
    assert!(msg.hdr.seq_num.is_none());

    assert!(msg.tlv_block.next().is_none());

    println!("pkt {:?}", pkt);
    println!("msg {:?}", msg.address_tlv);

    for pair in msg.address_tlv {
        let _pair = pair.unwrap();
    }
}
