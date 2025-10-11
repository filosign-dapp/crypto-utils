use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

#[wasm_bindgen]
pub struct SecretBuffer {
    ptr: *mut u8,
    len: usize,
}

#[wasm_bindgen]
impl SecretBuffer {
    #[wasm_bindgen(constructor)]
    pub fn new(len: usize) -> Result<SecretBuffer, JsValue> {
        let mut v = Vec::with_capacity(len);

        v.resize(len, 0u8);
        let ptr = v.as_mut_ptr();

        std::mem::forget(v);
        Ok(SecretBuffer { ptr, len })
    }

    #[wasm_bindgen(js_name = "write")]
    pub fn write_from_js(&mut self, data: &[u8]) -> Result<(), JsValue> {
        if data.len() > self.len {
            return Err(JsValue::from_str("data too long"));
        }
        unsafe {
            let dst = std::slice::from_raw_parts_mut(self.ptr, self.len);
            dst[..data.len()].copy_from_slice(data);
        }
        Ok(())
    }

    #[wasm_bindgen(js_name = "zeroize")]
    pub fn zeroize(&mut self) {
        unsafe {
            let dst = std::slice::from_raw_parts_mut(self.ptr, self.len);
            dst.zeroize();
        }
    }

    #[wasm_bindgen(js_name = "free")]
    pub fn free(mut self) {
        unsafe {
            let _ = Vec::from_raw_parts(self.ptr, self.len, self.len);
        }

        self.ptr = std::ptr::null_mut();
        self.len = 0;
    }

    #[wasm_bindgen(js_name = "ptr")]
    pub fn ptr(&self) -> u32 {
        self.ptr as u32
    }

    #[wasm_bindgen(js_name = "length")]
    pub fn length(&self) -> usize {
        self.len
    }
}

#[wasm_bindgen(js_name = "zeroize_raw")]
pub fn zeroize_raw(ptr: u32, len: usize) {
    if ptr == 0 || len == 0 {
        return;
    }
    let p = ptr as *mut u8;
    unsafe {
        let slice = std::slice::from_raw_parts_mut(p, len);
        slice.zeroize();
    }
}
