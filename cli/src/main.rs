use structopt::StructOpt;

#[derive(StructOpt, Debug)]
enum DIDKit {
    // DID Functionality
    /// Create new DID Document.
    DIDCreate {},
    /// Resolve a DID to a DID Document.
    DIDResolve {},
    /// Dereference a DID URL to a resource.
    DIDDereference {},
    /// Update a DID Document’s authentication.
    DIDUpdateAuthentication {},
    /// Update a DID Document’s service endpoint(s).
    DIDUpdateServiceEndpoints {},
    /// Deactivate a DID.
    DIDDeactivate {},
    /// Create a Signed IETF JSON Patch to update a DID document.
    DIDPatch {},

    // VC Functionality
    /// Issue Credential
    VCIssueCredential {},
    /// Verify Credential
    VCVerifyCredential {},
    /// Issue Presentation
    VCIssuePresentation {},
    /// Verify Presentation
    VCVerifyPresentation {},
    /// Revoke Credential
    VCRevokeCredential {},

    // DIDComm Functionality (???)
    /// Discover a messaging endpoint from a DID which supports DIDComm.
    DIDCommDiscover {},
    /// Send a DIDComm message.
    DIDCommSend {},
    /// Receive a DIDComm message.
    DIDCommReceive {},
}

fn main() {
    let opt = DIDKit::from_args();
    println!("{:?}", opt);
    // TODO
}
