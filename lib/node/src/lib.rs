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

    m.export_function("delegateCapability", didkit::delegate_capability)?;
    m.export_function(
        "prepareDelegateCapability",
        didkit::prepare_delegate_capability,
    )?;
    m.export_function(
        "completeDelegateCapability",
        didkit::complete_delegate_capability,
    )?;

    m.export_function("verifyDelegation", didkit::verify_delegation)?;

    m.export_function("invokeCapability", didkit::invoke_capability)?;
    m.export_function("prepareInvokeCapability", didkit::prepare_invoke_capability)?;
    m.export_function(
        "completeInvokeCapability",
        didkit::complete_invoke_capability,
    )?;

    m.export_function("verifyInvocation", didkit::verify_invocation)?;
    m.export_function(
        "verifyInvocationSignature",
        didkit::verify_invocation_signature,
    )?;

    m.export_function("jwkFromTezosKey", didkit::jwk_from_tezos_key)?;

    m.export_function("didResolve", didkit::did_resolve)?;

    Ok(())
});
