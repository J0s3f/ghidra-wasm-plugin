#![allow(dead_code)]
#[target_feature(enable = "simd128")]
unsafe fn dot(a: &[f32; 4], b: &[f32; 4]) -> f32 {
    use std::arch::wasm32::*;
    let va = v128_load(a.as_ptr() as *const v128);
    let vb = v128_load(b.as_ptr() as *const v128);
    let mut r: [f32; 4] = [0.0; 4];
    v128_store(r.as_mut_ptr() as *mut v128, f32x4_mul(va, vb));
    r.iter().sum()
}
#[no_mangle]
pub extern "C" fn dot4(a: *const f32, b: *const f32) -> f32 {
    use std::arch::wasm32::*;
    unsafe {
        let va = v128_load(a as *const v128);
        let vb = v128_load(b as *const v128);
        let mut r: [f32; 4] = [0.0; 4];
        v128_store(r.as_mut_ptr() as *mut v128, f32x4_mul(va, vb));
        r[0] + r[1] + r[2] + r[3]
    }
}
#[no_mangle]
pub extern "C" fn add4(a: *const i32, b: *const i32, o: *mut i32) {
    use std::arch::wasm32::*;
    unsafe {
        let va = v128_load(a as *const v128);
        let vb = v128_load(b as *const v128);
        v128_store(o as *mut v128, i32x4_add(va, vb));
    }
}

