use jni::objects::JClass;
use jni::sys::jstring;
use jni::JNIEnv;

pub static VERSION: &str = env!("CARGO_PKG_VERSION");

#[no_mangle]
pub extern "system" fn Java_com_spruceid_DIDKit_getVersion(env: JNIEnv, _class: JClass) -> jstring {
    env.new_string(VERSION)
        .expect("Unable to create Java string")
        .into_inner()
}
