use std::collections::BTreeMap;
#[no_mangle]
pub extern "C" fn fib(n: u32) -> u64 {
    let (mut a, mut b) = (0u64, 1u64);
    for _ in 0..n { let t = a.wrapping_add(b); a = b; b = t; }
    a
}
#[no_mangle]
pub extern "C" fn sum_slice(p: *const i32, n: usize) -> i64 {
    let s = unsafe { std::slice::from_raw_parts(p, n) };
    s.iter().map(|&x| x as i64).sum()
}
#[no_mangle]
pub extern "C" fn tally(p: *const u8, n: usize) -> u32 {
    let s = unsafe { std::slice::from_raw_parts(p, n) };
    let mut m: BTreeMap<u8, u32> = BTreeMap::new();
    for &b in s { *m.entry(b).or_insert(0) += 1; }
    m.values().copied().max().unwrap_or(0)
}
#[no_mangle]
pub extern "C" fn fmt(x: i32) -> usize { format!("v={} sq={}", x, (x as i64)*(x as i64)).len() }
