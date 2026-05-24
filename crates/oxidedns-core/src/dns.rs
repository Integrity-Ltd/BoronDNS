#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    Query = 0,
    Notify = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RecordType {
    A = 1,
    Ns = 2,
    Cname = 5,
    Soa = 6,
    Ptr = 12,
    Mx = 15,
    Txt = 16,
    Aaaa = 28,
    Srv = 33,
    Naptr = 35,
    Dname = 39,
    Ds = 43,
    Rrsig = 46,
    Nsec = 47,
    Dnskey = 48,
    Nsec3 = 50,
    Nsec3Param = 51,
    Tlsa = 52,
    Svcb = 64,
    Https = 65,
    Ixfr = 251,
    Axfr = 252,
    Tsig = 250,
    Opt = 41,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Rcode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp = 4,
    Refused = 5,
    NotAuth = 9,
}
