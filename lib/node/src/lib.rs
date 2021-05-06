use neon::prelude::*;

mod didkit;
mod error;
mod macros;

register_module!(mut m, {
    m.export_function("getVersion", didkit::get_version)?;

    m.export_function("generateEd25519Key", didkit::generate_ed25519_key)?;
    m.export_function("keyToDID", didkit::key_to_did)?;
    m.export_function(
        "keyToVerificationMethod",
        didkit::key_to_verification_method,
    )?;

    m.export_function("issueCredential", didkit::issue_credential)?;
    m.export_function("verifyCredential", didkit::verify_credential)?;

    m.export_function("issuePresentation", didkit::issue_presentation)?;
    m.export_function("verifyPresentation", didkit::verify_presentation)?;
    m.export_function("DIDAuth", didkit::did_auth)?;

    Ok(())
});
