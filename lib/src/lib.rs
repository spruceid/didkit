// pub use ssi::vc::Credential as VerifiableCredential;

use std::os::raw::c_char;

pub static VERSION: &str = env!("CARGO_PKG_VERSION");
pub static VERSION_C: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

#[no_mangle]
pub extern "C" fn didkit_get_version() -> *const c_char {
    VERSION_C.as_ptr() as *const c_char
}

use jni::objects::JClass;
use jni::sys::jstring;
use jni::JNIEnv;

#[no_mangle]
pub extern "system" fn Java_com_spruceid_DIDKit_getVersion(env: JNIEnv, _class: JClass) -> jstring {
    env.new_string(VERSION)
        .expect("Unable to create Java string")
        .into_inner()
}
