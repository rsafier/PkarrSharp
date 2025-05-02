use pkarr::{Client, PublicKey, SignedPacket, Keypair};
use pkarr::dns::rdata::{RData, A, AAAA};
use std::ptr;
use std::ffi::{CStr, CString};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::runtime::{Builder, Runtime};

// Structure to hold the result of the resolve operation
#[repr(C)]
pub struct ResolveResult {
    data: *mut u8,
    length: usize,
    error: *const i8,
}

// Structure to represent a DNS Resource Record for FFI
#[repr(C)]
pub struct ResourceRecord {
    name: *const i8,
    class: u16,
    ttl: u32,
    rdata_type: u16,
    rdata_data: *const i8,
    rdata_length: usize,
}

// Structure to represent a SignedPacket for FFI
#[repr(C)]
pub struct SignedPacketFFI {
    public_key: *const i8,
    timestamp: u64,
    last_seen: u64,
    records: *mut ResourceRecord,
    records_count: usize,
    raw_data: *mut u8,
    raw_length: usize,
}

// Global runtime and client for reuse across calls
lazy_static::lazy_static! {
    static ref RUNTIME: Arc<Mutex<Option<Runtime>>> = Arc::new(Mutex::new(None));
    static ref PKARR_CLIENT: Arc<Mutex<Option<Client>>> = Arc::new(Mutex::new(None));
}

#[no_mangle]
pub extern "C" fn pkarr_init() -> *const i8 {
    let mut rt_guard = RUNTIME.lock().unwrap();
    if rt_guard.is_some() {
        return CString::new("Runtime already initialized").unwrap().into_raw();
    }
    
    match Builder::new_current_thread()
        .enable_all()
        .build() {
        Ok(rt) => {
            *rt_guard = Some(rt);
            drop(rt_guard);
            
            let mut client_guard = PKARR_CLIENT.lock().unwrap();
            match Client::builder().build() {
                Ok(client) => {
                    *client_guard = Some(client);
                    ptr::null()
                }
                Err(e) => {
                    CString::new(format!("Failed to build client: {}", e)).unwrap().into_raw()
                }
            }
        }
        Err(e) => {
            CString::new(format!("Failed to build runtime: {}", e)).unwrap().into_raw()
        }
    }
}

#[no_mangle]
pub extern "C" fn pkarr_shutdown() {
    let mut rt_guard = RUNTIME.lock().unwrap();
    rt_guard.take();
    let mut client_guard = PKARR_CLIENT.lock().unwrap();
    client_guard.take();
}

// Helper function to convert RData to a string representation
fn rdata_to_string(rdata: &RData) -> (u16, String) {
    match rdata {
        RData::A(A { address }) => (1, format!("{:?}", std::net::Ipv4Addr::from(*address))),
        RData::AAAA(AAAA { address }) => (28, format!("{:?}", std::net::Ipv6Addr::from(*address))),
        RData::TXT(txt) => (16, txt.clone().try_into().unwrap_or_else(|_| "Invalid TXT".to_string())),
        RData::CNAME(cname) => (5, cname.to_string()),
        RData::MX(mx) => (15, format!("Preference: {}, Exchange: {}", mx.preference, mx.exchange.to_string())),
        RData::NS(ns) => (2, ns.to_string()),
        RData::PTR(ptr) => (12, ptr.to_string()),
        RData::SOA(soa) => (6, format!("MNAME: {}, RNAME: {}, SERIAL: {}, REFRESH: {}, RETRY: {}, EXPIRE: {}, MINIMUM: {}", 
            soa.mname.to_string(), soa.rname.to_string(), soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum)),
        RData::HTTPS(https) => (0, https.target.to_string()),
        _ => (0, format!("Unsupported RData type: {:?}", rdata)),
    }
}

// Convert a SignedPacket to a FFI-friendly structure
fn signed_packet_to_ffi(packet: &SignedPacket) -> SignedPacketFFI {
    let public_key = CString::new(packet.public_key().to_z32()).unwrap().into_raw();
    let timestamp = packet.timestamp().as_u64();
    let last_seen = packet.last_seen().as_u64();
    let raw_data = packet.as_bytes().to_vec();
    let raw_length = raw_data.len();
    let mut raw_data_boxed = raw_data.into_boxed_slice();
    let raw_data_ptr = raw_data_boxed.as_mut_ptr();
    std::mem::forget(raw_data_boxed);

    let records: Vec<ResourceRecord> = packet.all_resource_records().map(|rr| {
        let (rdata_type, rdata_str) = rdata_to_string(&rr.rdata);
        let rdata_str_clone = rdata_str.clone();
        ResourceRecord {
            name: CString::new(rr.name.to_string()).unwrap().into_raw(),
            class: rr.class as u16,
            ttl: rr.ttl,
            rdata_type,
            rdata_data: CString::new(rdata_str).unwrap().into_raw(),
            rdata_length: rdata_str_clone.len(),
        }
    }).collect();
    
    let records_count = records.len();
    let mut records_boxed = records.into_boxed_slice();
    let records_ptr = records_boxed.as_mut_ptr();
    std::mem::forget(records_boxed);

    SignedPacketFFI {
        public_key,
        timestamp,
        last_seen,
        records: records_ptr,
        records_count,
        raw_data: raw_data_ptr,
        raw_length,
    }
}

#[no_mangle]
pub extern "C" fn pkarr_free_signed_packet_ffi(packet: SignedPacketFFI) {
    if !packet.public_key.is_null() {
        unsafe {
            let _ = CString::from_raw(packet.public_key as *mut i8);
        }
    }
    if !packet.raw_data.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(packet.raw_data, packet.raw_length, packet.raw_length);
        }
    }
    if !packet.records.is_null() {
        unsafe {
            let records = Vec::from_raw_parts(packet.records, packet.records_count, packet.records_count);
            for record in records {
                if !record.name.is_null() {
                    let _ = CString::from_raw(record.name as *mut i8);
                }
                if !record.rdata_data.is_null() {
                    let _ = CString::from_raw(record.rdata_data as *mut i8);
                }
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn pkarr_resolve(public_key_str: *const i8, most_recent: bool) -> ResolveResult {
    let rt_guard = RUNTIME.lock().unwrap();
    let Some(ref rt) = *rt_guard else {
        return ResolveResult {
            data: ptr::null_mut(),
            length: 0,
            error: CString::new("Runtime not initialized. Call pkarr_init() first.").unwrap().into_raw(),
        };
    };
    
    let client_guard = PKARR_CLIENT.lock().unwrap();
    let Some(ref client) = *client_guard else {
        return ResolveResult {
            data: ptr::null_mut(),
            length: 0,
            error: CString::new("Client not initialized. Call pkarr_init() first.").unwrap().into_raw(),
        };
    };
    
    let result = rt.block_on(async {
        let c_str = unsafe { CStr::from_ptr(public_key_str) };
        let public_key_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                return ResolveResult {
                    data: ptr::null_mut(),
                    length: 0,
                    error: CString::new("Invalid public key string").unwrap().into_raw(),
                };
            }
        };

        let public_key: PublicKey = match public_key_str.try_into() {
            Ok(pk) => pk,
            Err(_) => {
                return ResolveResult {
                    data: ptr::null_mut(),
                    length: 0,
                    error: CString::new("Invalid zbase32 encoded key").unwrap().into_raw(),
                };
            }
        };

        let _start = Instant::now();
        let signed_packet = if most_recent {
            client.resolve_most_recent(&public_key).await
        } else {
            client.resolve(&public_key).await
        };

        match signed_packet {
            Some(packet) => {
                let ffi_packet = signed_packet_to_ffi(&packet);
                let ffi_packet_ptr = Box::new(ffi_packet);
                let data_ptr = Box::into_raw(ffi_packet_ptr) as *mut u8;
                ResolveResult {
                    data: data_ptr,
                    length: std::mem::size_of::<SignedPacketFFI>(),
                    error: ptr::null(),
                }
            }
            None => ResolveResult {
                data: ptr::null_mut(),
                length: 0,
                error: CString::new("No data found for the given public key").unwrap().into_raw(),
            }
        }
    });

    result
}

#[no_mangle]
pub extern "C" fn pkarr_generate_keypair() -> ResolveResult {
    let keypair = Keypair::random();
    let public_key = keypair.public_key().to_z32();
    let private_key = keypair.secret_key().to_vec(); // Convert secret key to Vec<u8>
    let private_key_hex = private_key.iter().map(|b| format!("{:02x}", b)).collect::<String>(); // Convert to hex string
    
    // Concatenate public and private keys with a delimiter
    let keypair_str = format!("{}|{}", public_key, private_key_hex);
    let keypair_bytes = keypair_str.into_bytes();
    let length = keypair_bytes.len();
    let mut data = keypair_bytes.into_boxed_slice();
    let data_ptr = data.as_mut_ptr();
    std::mem::forget(data);
    
    ResolveResult {
        data: data_ptr,
        length,
        error: ptr::null(),
    }
}

#[no_mangle]
pub extern "C" fn pkarr_publish(public_key_str: *const i8, private_key_str: *const i8, txt_key: *const i8, txt_value: *const i8, ttl: u32) -> ResolveResult {
    let rt_guard = RUNTIME.lock().unwrap();
    let Some(ref rt) = *rt_guard else {
        return ResolveResult {
            data: ptr::null_mut(),
            length: 0,
            error: CString::new("Runtime not initialized. Call pkarr_init() first.").unwrap().into_raw(),
        };
    };
    
    let client_guard = PKARR_CLIENT.lock().unwrap();
    let Some(ref client) = *client_guard else {
        return ResolveResult {
            data: ptr::null_mut(),
            length: 0,
            error: CString::new("Client not initialized. Call pkarr_init() first.").unwrap().into_raw(),
        };
    };
    
    let result = rt.block_on(async {
        let public_key_c_str = unsafe { CStr::from_ptr(public_key_str) };
        let public_key_str = match public_key_c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                return ResolveResult {
                    data: ptr::null_mut(),
                    length: 0,
                    error: CString::new("Invalid public key string").unwrap().into_raw(),
                };
            }
        };

        let private_key_c_str = unsafe { CStr::from_ptr(private_key_str) };
        let private_key_str = match private_key_c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                return ResolveResult {
                    data: ptr::null_mut(),
                    length: 0,
                    error: CString::new("Invalid private key string").unwrap().into_raw(),
                };
            }
        };

        let txt_key_c_str = unsafe { CStr::from_ptr(txt_key) };
        let txt_key_str = match txt_key_c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                return ResolveResult {
                    data: ptr::null_mut(),
                    length: 0,
                    error: CString::new("Invalid TXT key string").unwrap().into_raw(),
                };
            }
        };

        let txt_value_c_str = unsafe { CStr::from_ptr(txt_value) };
        let txt_value_str = match txt_value_c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                return ResolveResult {
                    data: ptr::null_mut(),
                    length: 0,
                    error: CString::new("Invalid TXT value string").unwrap().into_raw(),
                };
            }
        };

        // Convert private key from hex string to bytes
        let private_key_bytes = match hex::decode(private_key_str) {
            Ok(bytes) => bytes,
            Err(e) => {
                return ResolveResult {
                    data: ptr::null_mut(),
                    length: 0,
                    error: CString::new(format!("Invalid private key format: {}", e)).unwrap().into_raw(),
                };
            }
        };

        if private_key_bytes.len() != 32 {
            return ResolveResult {
                data: ptr::null_mut(),
                length: 0,
                error: CString::new("Private key must be 32 bytes").unwrap().into_raw(),
            };
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&private_key_bytes);
        let keypair = pkarr::Keypair::from_secret_key(&key_bytes);
        
        let signed_packet = match SignedPacket::builder()
            .txt(txt_key_str.try_into().unwrap(), txt_value_str.try_into().unwrap(), ttl)
            .sign(&keypair)
        {
            Ok(sp) => sp,
            Err(e) => {
                return ResolveResult {
                    data: ptr::null_mut(),
                    length: 0,
                    error: CString::new(format!("Failed to create signed packet: {}", e)).unwrap().into_raw(),
                };
            }
        };

        // Verify that the public key matches
        if keypair.public_key().to_z32() != public_key_str {
            return ResolveResult {
                data: ptr::null_mut(),
                length: 0,
                error: CString::new("Provided public key does not match the private key").unwrap().into_raw(),
            };
        }

        match client.publish(&signed_packet, None).await {
            Ok(()) => {
                let success_msg = format!("Published successfully for {}", public_key_str);
                let bytes = success_msg.into_bytes();
                let length = bytes.len();
                let mut data = bytes.into_boxed_slice();
                let data_ptr = data.as_mut_ptr();
                std::mem::forget(data);
                ResolveResult {
                    data: data_ptr,
                    length,
                    error: ptr::null(),
                }
            }
            Err(e) => {
                ResolveResult {
                    data: ptr::null_mut(),
                    length: 0,
                    error: CString::new(format!("Failed to publish: {}", e)).unwrap().into_raw(),
                }
            }
        }
    });

    result
}

#[no_mangle]
pub extern "C" fn pkarr_free_result(result: ResolveResult) {
    // This function only frees the error string if it exists
    // The data must be freed by the specific free function for each type
    if !result.error.is_null() {
        unsafe {
            let _ = CString::from_raw(result.error as *mut i8);
        }
    }
}
