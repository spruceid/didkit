use didkit::{
    dereference, get_verification_method, Error, JWTOrLDPOptions, ProofFormat, Source,
    VerifiableCredential, VerifiablePresentation, DID_METHODS, JWK, URI,
};
use pyo3::{
    create_exception,
    exceptions::{PyException, PyValueError},
    prelude::*,
};
use serde_json;
use std::convert::From;

pub static VERSION: &str = env!("CARGO_PKG_VERSION");

create_exception!(didkit, DIDKitException, PyException);

#[pymodule]
fn pydidkit(py: Python, m: &PyModule) -> PyResult<()> {
    m.add("DIDKitException", py.get_type::<DIDKitException>())?;

    #[pyfn(m)]
    #[pyo3(text_signature = "(, /)")]
    fn get_version(_py: Python) -> String {
        VERSION.into()
    }

    #[pyfn(m)]
    #[pyo3(text_signature = "(, /)")]
    fn generate_ed25519_key(_py: Python) -> PyResult<String> {
        Ok(serde_json::to_string(
            &JWK::generate_ed25519().map_err(|e| DIDKitException::new_err(e.to_string()))?,
        )
        .map_err(|e| PyValueError::new_err(e.to_string()))?)
    }

    #[pyfn(m)]
    #[pyo3(text_signature = "(method_pattern, jwk, /)")]
    fn key_to_did(_py: Python, method_pattern: String, jwk: String) -> PyResult<String> {
        let key: JWK =
            serde_json::from_str(&jwk).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let did = DID_METHODS
            .generate(&Source::KeyAndPattern(&key, &method_pattern))
            .ok_or(Error::UnableToGenerateDID)
            .map_err(|e| DIDKitException::new_err(e.to_string()))?;
        Ok(did)
    }

    #[pyfn(m)]
    #[pyo3(text_signature = "(method_pattern, jwk, /)")]
    fn key_to_verification_method(
        py: Python,
        method_pattern: String,
        jwk: String,
    ) -> PyResult<&PyAny> {
        let key: JWK =
            serde_json::from_str(&jwk).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let did = DID_METHODS
            .generate(&Source::KeyAndPattern(&key, &method_pattern))
            .ok_or(Error::UnableToGenerateDID)
            .map_err(|e| DIDKitException::new_err(e.to_string()))?;
        let did_resolver = DID_METHODS.to_resolver();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let vm = get_verification_method(&did, did_resolver)
                .await
                .ok_or(Error::UnableToGetVerificationMethod)
                .map_err(|e| DIDKitException::new_err(e.to_string()))?;
            Ok(Python::with_gil(|py| vm.into_py(py)))
        })
    }

    #[pyfn(m)]
    #[pyo3(text_signature = "(credential, proof_options, key, /)")]
    fn issue_credential(
        py: Python,
        credential: String,
        proof_options: String,
        key: String,
    ) -> PyResult<&PyAny> {
        let mut credential = VerifiableCredential::from_json_unsigned(&credential)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let key: JWK =
            serde_json::from_str(&key).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let resolver = DID_METHODS.to_resolver();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let options: JWTOrLDPOptions = serde_json::from_str(&proof_options)
                .map_err(|e| PyValueError::new_err(e.to_string()))?;
            let proof_format = options.proof_format.unwrap_or_default();
            let vc_string = match proof_format {
                ProofFormat::JWT => {
                    let vc_jwt = credential
                        .generate_jwt(Some(&key), &options.ldp_options, resolver)
                        .await
                        .map_err(|e| DIDKitException::new_err(e.to_string()))?;
                    vc_jwt
                }
                ProofFormat::LDP => {
                    let proof = credential
                        .generate_proof(&key, &options.ldp_options, resolver)
                        .await
                        .map_err(|e| DIDKitException::new_err(e.to_string()))?;
                    credential.add_proof(proof);
                    let vc_json = serde_json::to_string(&credential)
                        .map_err(|e| PyValueError::new_err(e.to_string()))?;
                    vc_json
                }
                _ => Err(Error::UnknownProofFormat(proof_format.to_string()))
                    .map_err(|e| DIDKitException::new_err(e.to_string()))?,
            };
            Ok(Python::with_gil(|py| vc_string.into_py(py)))
        })
    }

    #[pyfn(m)]
    #[pyo3(text_signature = "(credential, proof_options, /)")]
    fn verify_credential(
        py: Python,
        credential: String,
        proof_options: String,
    ) -> PyResult<&PyAny> {
        let resolver = DID_METHODS.to_resolver();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let options: JWTOrLDPOptions = serde_json::from_str(&proof_options)
                .map_err(|e| PyValueError::new_err(e.to_string()))?;
            let proof_format = options.proof_format.unwrap_or_default();
            let result = match proof_format {
                ProofFormat::JWT => {
                    VerifiableCredential::verify_jwt(
                        &credential,
                        Some(options.ldp_options),
                        resolver,
                    )
                    .await
                }
                ProofFormat::LDP => {
                    let vc = VerifiableCredential::from_json_unsigned(&credential)
                        .map_err(|e| PyValueError::new_err(e.to_string()))?;
                    vc.verify(Some(options.ldp_options), resolver).await
                }
                _ => Err(Error::UnknownProofFormat(proof_format.to_string()))
                    .map_err(|e| DIDKitException::new_err(e.to_string()))?,
            };
            let result_json =
                serde_json::to_string(&result).map_err(|e| PyValueError::new_err(e.to_string()))?;
            Ok(Python::with_gil(|py| result_json.into_py(py)))
        })
    }

    #[pyfn(m)]
    #[pyo3(text_signature = "(presentation, proof_options, key, /)")]
    fn issue_presentation(
        py: Python,
        presentation: String,
        proof_options: String,
        key: String,
    ) -> PyResult<&PyAny> {
        let mut presentation = VerifiablePresentation::from_json_unsigned(&presentation)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let key: JWK =
            serde_json::from_str(&key).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let resolver = DID_METHODS.to_resolver();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let options: JWTOrLDPOptions = serde_json::from_str(&proof_options)
                .map_err(|e| PyValueError::new_err(e.to_string()))?;
            let proof_format = options.proof_format.unwrap_or_default();
            let vc_string = match proof_format {
                ProofFormat::JWT => {
                    let vc_jwt = presentation
                        .generate_jwt(Some(&key), &options.ldp_options, resolver)
                        .await
                        .map_err(|e| DIDKitException::new_err(e.to_string()))?;
                    vc_jwt
                }
                ProofFormat::LDP => {
                    let proof = presentation
                        .generate_proof(&key, &options.ldp_options, resolver)
                        .await
                        .map_err(|e| DIDKitException::new_err(e.to_string()))?;
                    presentation.add_proof(proof);
                    let vc_json = serde_json::to_string(&presentation)
                        .map_err(|e| PyValueError::new_err(e.to_string()))?;
                    vc_json
                }
                _ => Err(Error::UnknownProofFormat(proof_format.to_string()))
                    .map_err(|e| DIDKitException::new_err(e.to_string()))?,
            };
            Ok(Python::with_gil(|py| vc_string.into_py(py)))
        })
    }

    #[pyfn(m)]
    #[pyo3(text_signature = "(presentation, proof_options, /)")]
    fn verify_presentation(
        py: Python,
        presentation: String,
        proof_options: String,
    ) -> PyResult<&PyAny> {
        let resolver = DID_METHODS.to_resolver();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let options: JWTOrLDPOptions = serde_json::from_str(&proof_options)
                .map_err(|e| PyValueError::new_err(e.to_string()))?;
            let proof_format = options.proof_format.unwrap_or_default();
            let result = match proof_format {
                ProofFormat::JWT => {
                    VerifiablePresentation::verify_jwt(
                        &presentation,
                        Some(options.ldp_options),
                        resolver,
                    )
                    .await
                }
                ProofFormat::LDP => {
                    let vc = VerifiablePresentation::from_json_unsigned(&presentation)
                        .map_err(|e| PyValueError::new_err(e.to_string()))?;
                    vc.verify(Some(options.ldp_options), resolver).await
                }
                _ => Err(Error::UnknownProofFormat(proof_format.to_string()))
                    .map_err(|e| DIDKitException::new_err(e.to_string()))?,
            };
            let result_json = serde_json::to_string(&result)
                .map_err(|e| DIDKitException::new_err(e.to_string()))?;
            Ok(Python::with_gil(|py| result_json.into_py(py)))
        })
    }

    #[pyfn(m)]
    #[pyo3(text_signature = "(did, input_metadata, /)")]
    fn resolve_did(py: Python, did: String, input_metadata: String) -> PyResult<&PyAny> {
        let resolver = DID_METHODS.to_resolver();
        let input_metadata = serde_json::from_str(&input_metadata)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let (res_meta, doc, _) = resolver.resolve(&did, &input_metadata).await;

            if let Some(error) = res_meta.error {
                return Err(DIDKitException::new_err(error));
            }

            if let Some(d) = doc {
                let result_json = serde_json::to_string(&d)
                    .map_err(|e| DIDKitException::new_err(e.to_string()))?;
                Ok(Python::with_gil(|py| result_json.into_py(py)))
            } else {
                Err(DIDKitException::new_err(
                    "No document resolved.".to_string(),
                ))
            }
        })
    }

    #[pyfn(m)]
    #[pyo3(text_signature = "(did_url, input_metadata, /)")]
    fn dereference_did_url(
        py: Python,
        did_url: String,
        input_metadata: String,
    ) -> PyResult<&PyAny> {
        let resolver = DID_METHODS.to_resolver();
        let input_metadata = serde_json::from_str(&input_metadata)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let (deref_meta, doc, _) = dereference(resolver, &did_url, &input_metadata).await;

            if let Some(error) = deref_meta.error {
                return Err(DIDKitException::new_err(error));
            }

            let result_json =
                serde_json::to_string(&doc).map_err(|e| DIDKitException::new_err(e.to_string()))?;
            Ok(Python::with_gil(|py| result_json.into_py(py)))
        })
    }

    #[pyfn(m)]
    #[pyo3(text_signature = "(did, options, key, /)")]
    fn did_auth(py: Python, did: String, options: String, key: String) -> PyResult<&PyAny> {
        let mut presentation = VerifiablePresentation::default();
        presentation.holder = Some(URI::String(did));
        let key: JWK =
            serde_json::from_str(&key).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let resolver = DID_METHODS.to_resolver();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let options: JWTOrLDPOptions =
                serde_json::from_str(&options).map_err(|e| PyValueError::new_err(e.to_string()))?;
            let proof_format = options.proof_format.unwrap_or_default();
            let vp_string = match proof_format {
                ProofFormat::JWT => presentation
                    .generate_jwt(Some(&key), &options.ldp_options, resolver)
                    .await
                    .map_err(|e| DIDKitException::new_err(e.to_string()))?,
                ProofFormat::LDP => {
                    let proof = presentation
                        .generate_proof(&key, &options.ldp_options, resolver)
                        .await
                        .map_err(|e| DIDKitException::new_err(e.to_string()))?;
                    presentation.add_proof(proof);
                    serde_json::to_string(&presentation)
                        .map_err(|e| DIDKitException::new_err(e.to_string()))?
                }
                _ => Err(Error::UnknownProofFormat(proof_format.to_string()))
                    .map_err(|e| DIDKitException::new_err(e.to_string()))?,
            };
            Ok(Python::with_gil(|py| vp_string.into_py(py)))
        })
    }

    Ok(())
}
