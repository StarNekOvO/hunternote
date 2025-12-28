use wasm_bindgen::prelude::*;
use md5::{Md5, Digest as Md5Digest};
use sha1::{Sha1, Digest as Sha1Digest};
use sha2::{Sha256, Sha512, Digest as Sha2Digest};

// ============ Hash Functions ============

#[wasm_bindgen]
pub fn hash_md5(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[wasm_bindgen]
pub fn hash_sha1(data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[wasm_bindgen]
pub fn hash_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[wasm_bindgen]
pub fn hash_sha512(data: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

// ============ Encoding Functions ============

#[wasm_bindgen]
pub fn encode_base64(data: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    STANDARD.encode(data)
}

#[wasm_bindgen]
pub fn decode_base64(input: &str) -> Result<Vec<u8>, JsError> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    STANDARD.decode(input).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn encode_hex(data: &[u8]) -> String {
    hex::encode(data)
}

#[wasm_bindgen]
pub fn decode_hex(input: &str) -> Result<Vec<u8>, JsError> {
    let cleaned: String = input.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    hex::decode(&cleaned).map_err(|e| JsError::new(&e.to_string()))
}

// ============ PWN Helper Functions ============

#[wasm_bindgen]
pub fn to_little_endian(value: &str, bytes: usize) -> Result<String, JsError> {
    let cleaned = value.trim_start_matches("0x").trim_start_matches("0X");
    let num = u64::from_str_radix(cleaned, 16)
        .map_err(|e| JsError::new(&format!("Invalid hex: {}", e)))?;
    
    let le_bytes: Vec<u8> = num.to_le_bytes()[..bytes].to_vec();
    Ok(format!("0x{}", hex::encode(le_bytes)))
}

#[wasm_bindgen]
pub fn to_big_endian(value: &str, bytes: usize) -> Result<String, JsError> {
    let cleaned = value.trim_start_matches("0x").trim_start_matches("0X");
    let num = u64::from_str_radix(cleaned, 16)
        .map_err(|e| JsError::new(&format!("Invalid hex: {}", e)))?;
    
    let be_bytes: Vec<u8> = num.to_be_bytes()[(8-bytes)..].to_vec();
    Ok(format!("0x{}", hex::encode(be_bytes)))
}

#[wasm_bindgen]
pub fn calc_address(base: &str, offset: &str) -> Result<String, JsError> {
    let base_clean = base.trim_start_matches("0x").trim_start_matches("0X");
    let base_num = u64::from_str_radix(base_clean, 16)
        .map_err(|e| JsError::new(&format!("Invalid base: {}", e)))?;
    
    let is_negative = offset.starts_with('-');
    let offset_clean = offset
        .trim_start_matches('-')
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    
    let offset_num = u64::from_str_radix(offset_clean, 16)
        .map_err(|e| JsError::new(&format!("Invalid offset: {}", e)))?;
    
    let result = if is_negative {
        base_num.wrapping_sub(offset_num)
    } else {
        base_num.wrapping_add(offset_num)
    };
    
    Ok(format!("0x{:x}", result))
}

#[wasm_bindgen]
pub fn generate_padding(length: usize, pattern: char) -> String {
    std::iter::repeat(pattern).take(length).collect()
}

#[wasm_bindgen]
pub fn generate_cyclic(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..length)
        .map(|i| CHARSET[i % CHARSET.len()] as char)
        .collect()
}

// ============ Shellcode Functions ============

#[wasm_bindgen]
pub fn format_shellcode(input: &str, format: &str) -> String {
    // 提取所有 hex 字节
    let hex_bytes: Vec<String> = input
        .replace("\\x", " ")
        .replace("0x", " ")
        .replace(',', " ")
        .split_whitespace()
        .filter(|s| s.len() == 2 && s.chars().all(|c| c.is_ascii_hexdigit()))
        .map(|s| s.to_lowercase())
        .collect();
    
    if hex_bytes.is_empty() {
        return String::from("无法解析");
    }
    
    match format {
        "c" => format!("\"{}\"", hex_bytes.iter().map(|b| format!("\\x{}", b)).collect::<String>()),
        "python" => format!("b\"{}\"", hex_bytes.iter().map(|b| format!("\\x{}", b)).collect::<String>()),
        "hex" => hex_bytes.iter().map(|b| b.to_uppercase()).collect::<Vec<_>>().join(" "),
        "array" => format!("{{ {} }}", hex_bytes.iter().map(|b| format!("0x{}", b.to_uppercase())).collect::<Vec<_>>().join(", ")),
        "nasm" => format!("db {}", hex_bytes.iter().map(|b| format!("0x{}", b)).collect::<Vec<_>>().join(", ")),
        _ => hex_bytes.join("")
    }
}

#[wasm_bindgen]
pub fn shellcode_length(input: &str) -> usize {
    input
        .replace("\\x", " ")
        .replace("0x", " ")
        .replace(',', " ")
        .split_whitespace()
        .filter(|s| s.len() == 2 && s.chars().all(|c| c.is_ascii_hexdigit()))
        .count()
}

// ============ Base Converter Functions ============

#[wasm_bindgen]
pub fn convert_base(value: &str, from_base: u32) -> Result<String, JsError> {
    if value.is_empty() {
        return Ok(String::new());
    }
    
    let num = match from_base {
        2 => i128::from_str_radix(value, 2),
        8 => i128::from_str_radix(value, 8),
        10 => value.parse::<i128>(),
        16 => i128::from_str_radix(value, 16),
        _ => return Err(JsError::new("Unsupported base")),
    };
    
    let num = num.map_err(|e| JsError::new(&e.to_string()))?;
    
    // Return as JSON object string
    Ok(format!(
        r#"{{"dec":"{}","bin":"{}","oct":"{}","hex":"{}"}}"#,
        num,
        format!("{:b}", num),
        format!("{:o}", num),
        format!("{:X}", num)
    ))
}

// ============ Timestamp Functions ============

#[wasm_bindgen]
pub fn timestamp_to_date(ts: f64) -> String {
    // ts is in seconds, convert to more usable format
    let mut timestamp = ts as i64;
    
    // If timestamp is in milliseconds (> year 3000 in seconds)
    if timestamp > 32503680000 {
        timestamp /= 1000;
    }
    
    // Calculate date components from Unix timestamp
    // This is a simplified calculation
    let seconds_per_minute = 60i64;
    let seconds_per_hour = 3600i64;
    let seconds_per_day = 86400i64;
    
    let days_since_epoch = timestamp / seconds_per_day;
    let time_of_day = timestamp % seconds_per_day;
    
    let hours = time_of_day / seconds_per_hour;
    let minutes = (time_of_day % seconds_per_hour) / seconds_per_minute;
    let seconds = time_of_day % seconds_per_minute;
    
    // Calculate year, month, day from days since epoch
    let (year, month, day) = days_to_ymd(days_since_epoch);
    
    format!(
        r#"{{"year":{},"month":{},"day":{},"hours":{},"minutes":{},"seconds":{}}}"#,
        year, month, day, hours, minutes, seconds
    )
}

fn days_to_ymd(days: i64) -> (i32, i32, i32) {
    // Days since 1970-01-01
    let mut remaining = days;
    let mut year = 1970i32;
    
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        year += 1;
    }
    
    let leap = is_leap_year(year);
    let days_in_months = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    
    let mut month = 1;
    for days_in_month in days_in_months.iter() {
        if remaining < *days_in_month {
            break;
        }
        remaining -= days_in_month;
        month += 1;
    }
    
    (year, month, remaining as i32 + 1)
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

#[wasm_bindgen]
pub fn date_to_timestamp(year: i32, month: i32, day: i32, hours: i32, minutes: i32, seconds: i32) -> i64 {
    // Calculate days from epoch to given date
    let mut days = 0i64;
    
    // Years
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    
    // Months
    let leap = is_leap_year(year);
    let days_in_months = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    
    for m in 0..(month - 1) as usize {
        days += days_in_months[m] as i64;
    }
    
    // Days
    days += (day - 1) as i64;
    
    // Convert to seconds and add time
    days * 86400 + hours as i64 * 3600 + minutes as i64 * 60 + seconds as i64
}

// ============ IP/CIDR Functions ============

#[wasm_bindgen]
pub fn parse_cidr(cidr: &str) -> Result<String, JsError> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(JsError::new("Invalid CIDR format. Expected: x.x.x.x/prefix"));
    }
    
    let ip = parse_ipv4(parts[0])?;
    let prefix: u8 = parts[1].parse().map_err(|_| JsError::new("Invalid prefix length"))?;
    
    if prefix > 32 {
        return Err(JsError::new("Prefix must be 0-32"));
    }
    
    let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
    let network = ip & mask;
    let broadcast = network | !mask;
    let host_count = if prefix >= 31 { 
        2u32.pow(32 - prefix as u32) 
    } else { 
        2u32.pow(32 - prefix as u32) - 2 
    };
    
    let first_host = if prefix >= 31 { network } else { network + 1 };
    let last_host = if prefix >= 31 { broadcast } else { broadcast - 1 };
    
    Ok(format!(
        "{{\"ip\":\"{}\",\"prefix\":{},\"netmask\":\"{}\",\"wildcard\":\"{}\",\"network\":\"{}\",\"broadcast\":\"{}\",\"firstHost\":\"{}\",\"lastHost\":\"{}\",\"hostCount\":{}}}",
        ip_to_string(ip),
        prefix,
        ip_to_string(mask),
        ip_to_string(!mask),
        ip_to_string(network),
        ip_to_string(broadcast),
        ip_to_string(first_host),
        ip_to_string(last_host),
        host_count
    ))
}

#[wasm_bindgen]
pub fn ip_to_binary(ip: &str) -> Result<String, JsError> {
    let ip_num = parse_ipv4(ip)?;
    Ok(format!("{:032b}", ip_num))
}

#[wasm_bindgen]
pub fn ip_to_hex(ip: &str) -> Result<String, JsError> {
    let ip_num = parse_ipv4(ip)?;
    Ok(format!("{:08X}", ip_num))
}

#[wasm_bindgen]
pub fn ip_to_decimal(ip: &str) -> Result<u32, JsError> {
    parse_ipv4(ip)
}

#[wasm_bindgen]
pub fn decimal_to_ip(decimal: u32) -> String {
    ip_to_string(decimal)
}

#[wasm_bindgen]
pub fn is_private_ip(ip: &str) -> Result<bool, JsError> {
    let ip_num = parse_ipv4(ip)?;
    let octets = [
        ((ip_num >> 24) & 0xFF) as u8,
        ((ip_num >> 16) & 0xFF) as u8,
        ((ip_num >> 8) & 0xFF) as u8,
        (ip_num & 0xFF) as u8,
    ];
    
    // 10.0.0.0/8
    if octets[0] == 10 {
        return Ok(true);
    }
    // 172.16.0.0/12
    if octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31 {
        return Ok(true);
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return Ok(true);
    }
    // 127.0.0.0/8 (loopback)
    if octets[0] == 127 {
        return Ok(true);
    }
    
    Ok(false)
}

#[wasm_bindgen]
pub fn get_ip_class(ip: &str) -> Result<String, JsError> {
    let ip_num = parse_ipv4(ip)?;
    let first_octet = ((ip_num >> 24) & 0xFF) as u8;
    
    let class = if first_octet < 128 {
        "A"
    } else if first_octet < 192 {
        "B"
    } else if first_octet < 224 {
        "C"
    } else if first_octet < 240 {
        "D (Multicast)"
    } else {
        "E (Reserved)"
    };
    
    Ok(class.to_string())
}

fn parse_ipv4(ip: &str) -> Result<u32, JsError> {
    let octets: Vec<&str> = ip.trim().split('.').collect();
    if octets.len() != 4 {
        return Err(JsError::new("Invalid IPv4 address"));
    }
    
    let mut result: u32 = 0;
    for (i, octet) in octets.iter().enumerate() {
        let num: u8 = octet.parse().map_err(|_| JsError::new("Invalid octet"))?;
        result |= (num as u32) << (24 - i * 8);
    }
    
    Ok(result)
}

fn ip_to_string(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF
    )
}
