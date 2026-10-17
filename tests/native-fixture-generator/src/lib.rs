//! Test-only public-vector generator. No code is built outside cfg(test).
#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use libsec_core::ZenithPacket;
    use secs_server::receipt::AuthenticatorKind;
    use secs_server::verifier::{VerifiedCallContext, VerifiedSubject};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    #[test]
    fn generate_public_vectors() {
        let input = std::env::var("FRANK_FIXTURE_INPUT").expect("explicit input");
        let output = std::env::var("FRANK_FIXTURE_OUTPUT").expect("explicit output");
        assert!(
            !std::path::Path::new(&output).exists(),
            "create-only output"
        );
        let cases: Vec<Value> = serde_json::from_slice(&std::fs::read(input).unwrap()).unwrap();
        let mut vectors = Vec::new();
        for case in cases {
            let packet = ZenithPacket {
                session_id: [1; 16],
                nonce: [case["nonce"].as_u64().unwrap() as u8; 12],
                opcode: case["opcode"].as_u64().unwrap() as u8,
                proof: vec![3, 4],
                claim_ttl: 60,
                encrypted_payload: case["payload"].as_str().unwrap().as_bytes().to_vec(),
                mac: [0; 16],
            };
            let packet_bytes = bincode::serialize(&packet).unwrap();
            let issued = case["issued"].as_u64().unwrap();
            let context = VerifiedCallContext {
                schema_version: 4,
                context_id: format!("synthetic-{}", case["name"].as_str().unwrap()),
                packet_hash: Sha256::digest(&packet_bytes).into(),
                session_id: packet.session_id,
                nonce: packet.nonce,
                opcode: packet.opcode,
                operation: case["operation"].as_str().unwrap().into(),
                resource: Some("runs/run/steps/step/attempts/attempt/effects/effect-1".into()),
                subject: VerifiedSubject {
                    subject_id: case["subject"].as_str().unwrap().into(),
                    key_id: "synthetic-holder".into(),
                },
                audience: case["audience"].as_str().unwrap().into(),
                evidence_summary: vec![],
                proof_metadata: None,
                capability_result: "frank.result.attest".into(),
                credential_result: "synthetic-only".into(),
                issued_at: issued,
                expires_at: issued + 60,
                descriptor_fingerprint: "a".repeat(64),
                replay_scope: "session:opcode:nonce".into(),
                handler_id: Some("frank-result-test".into()),
            };
            // Disposable known test seed, compiled only into this non-shipped test crate.
            let signed = context
                .sign_ed25519(
                    "synthetic-verifier",
                    &[17; 32],
                    AuthenticatorKind::Ed25519NodeAndVerifier,
                )
                .unwrap();
            let mut result = case["result"].clone();
            result["proof"] = json!({"schema":"frank.secs-result-envelope.v1","packet_hex":hex::encode(packet_bytes),"signed_context_hex":hex::encode(bincode::serialize(&signed).unwrap())});
            vectors.push(json!({"name":case["name"],"work":case["work"],"result":result,"now_seconds":issued+1}));
        }
        let document = json!({"schema":"frank.synthetic-native-result-fixtures.v1","secs_revision":"11e7128e49c6df57f53e4c8b05e72d4bc78d798c","public_key_hex":hex::encode(SigningKey::from_bytes(&[17;32]).verifying_key().as_bytes()),"qualification":"historical synthetic context compatibility only; not caller/issuer/producer qualification","fixtures":vectors});
        std::fs::write(output, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
    }
}
