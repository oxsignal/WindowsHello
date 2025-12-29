
## Windows Hello Hardware Authentication Flow

### Phase 1: Device Registration & Key Generation + Attestation

This phase occurs when a user registers their device for the first time.

1. **Client**: Calls the `KeyCredentialManager` API, which triggers the Windows Hello UI (Biometric/PIN prompt).
2. **TPM (Hardware)**: Upon successful user verification, the TPM generates an **RSA Key Pair** inside its secure boundary. These keys are non-exportable.
3. **Client**:
* Extracts the **Public Key (SPKI)**.
* Retrieves the **Attestation Data** from the TPM:
* **`CertificateChainBuffer`**: A chain of certificates (approx. 14KB) tracing back from the hardware vendor (e.g., AMD/Intel) to the **Microsoft Root CA**.
* **`AttestationBuffer`**: A binary report (containing the `KYAT` magic number) proving that the public key was indeed generated inside that specific TPM.
4. **Server**: Receives and validates the data:
* **Trust Chain Verification**: Compares the root certificate's thumbprint against the whitelist extracted from **`TrustedTpm.cab`** to ensure the device is a genuine, Microsoft-certified TPM. The list of root certificates required for verification is obtained by downloading the TrustedTpm.cab file from the [official Microsoft URL](https://go.microsoft.com/fwlink/?linkid=2097925).

* **Key Binding Verification**: Confirms that the public key provided by the client is the same one contained within the signed Attestation Buffer.
* **Persistence**: Stores the validated public key mapped to the user’s ID.



### Phase 2: Challenge Request

Every login attempt begins with a unique challenge to prevent replay attacks.
1. **Client**: Notifies the server of a login attempt (e.g., "I am user 'abcd'").
2. **Server**: Generates a cryptographically strong random value called a **Challenge (Nonce)** and sends it to the client.

### Phase 3: Hardware Signing

The user authorizes the use of the private key via biometrics.
1. **Client**: Passes the server’s challenge to the Windows Hello signing API.
2. **User**: Authenticates via fingerprint, face, or PIN.
3. **TPM (Hardware)**: Once the user is verified, the TPM uses the **internal Private Key** to sign the challenge data.
4. **Client**: Sends the resulting **Digital Signature** to the server.

### Phase 4: Final Verification & Approval

The server performs a mathematical check to grant access.

1. **Server**:
* Retrieves the user's registered **Public Key** from the database.
* Verifies the **Signature** against the original **Challenge**.

2. **Result**: If the signature is valid, the user is authenticated. The challenge is immediately invalidated to prevent reuse.