package in.bitanxen.poc.service.jwt.signer;

import com.google.common.base.Strings;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import in.bitanxen.poc.config.bean.JWKSetKeyStore;
import in.bitanxen.poc.util.CommonUtil;
import lombok.Setter;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@Log4j2
public class JWTSignerVerifierServiceImpl implements JWTSignerVerifierService {

    private final Map<String, JWSSigner> signers = new HashMap<>();
    private final Map<String, JWSVerifier> verifiers = new HashMap<>();
    private Map<String, JWK> keys = new HashMap<>();

    @Setter
    @Value("${sysbean.oauth2.server.config.jwk.signer-key}")
    private String defaultSignerKeyId;

    @Setter
    @Value("${sysbean.oauth2.server.config.jwk.signer-algo}")
    private String defaultSigningAlgorithmName;

    @Setter
    private JWSAlgorithm defaultAlgorithm;

    public JWTSignerVerifierServiceImpl(Map<String, JWK> keys) {
        this.keys = keys;
        buildSignersAndVerifiers();
    }

    @Autowired
    public JWTSignerVerifierServiceImpl(JWKSetKeyStore keyStore) {
        if (keyStore != null && keyStore.getJwkSet() != null) {
            for (JWK key : keyStore.getKeys()) {
                if (!Strings.isNullOrEmpty(key.getKeyID())) {
                    this.keys.put(key.getKeyID(), key);
                } else {
                    String kid = UUID.randomUUID().toString();
                    this.keys.put(kid, key);
                }
            }
            buildSignersAndVerifiers();
        }
        defaultAlgorithm = JWSAlgorithm.parse(defaultSigningAlgorithmName);
    }

    @Override
    public Map<String, JWK> getAllPublicKeys() {
        return CommonUtil.getJWKPublicKeys(keys);
    }

    @Override
    public boolean validateSignature(SignedJWT jwt) {
        for (JWSVerifier verifier : verifiers.values()) {
            try {
                if (jwt.verify(verifier)) {
                    return true;
                }
            } catch (JOSEException e) {
                log.error("Failed to validate signature with {} error message: {}", verifier, e.getMessage());
            }
        }
        return false;
    }

    @Override
    public void signJwt(SignedJWT jwt) {
        if (getDefaultSignerKeyId() == null) {
            throw new IllegalStateException("Tried to call default signing with no default signer ID set");
        }

        JWSSigner signer = signers.get(getDefaultSignerKeyId());

        try {
            jwt.sign(signer);
        } catch (JOSEException e) {
            log.error("Failed to sign JWT, error was: ", e);
        }
    }

    @Override
    public JWSAlgorithm getDefaultSigningAlgorithm() {
        return defaultAlgorithm;
    }

    @Override
    public Collection<JWSAlgorithm> getAllSigningAlgsSupported() {
        Set<JWSAlgorithm> algs = new HashSet<>();

        for (JWSSigner signer : signers.values()) {
            algs.addAll(signer.supportedJWSAlgorithms());
        }

        for (JWSVerifier verifier : verifiers.values()) {
            algs.addAll(verifier.supportedJWSAlgorithms());
        }
        return algs;
    }

    @Override
    public void signJwt(SignedJWT jwt, JWSAlgorithm alg) {
        JWSSigner signer = null;

        for (JWSSigner s : signers.values()) {
            if (s.supportedJWSAlgorithms().contains(alg)) {
                signer = s;
                break;
            }
        }

        if (signer == null) {
            log.error("No matching algirthm found for alg: " + alg);
        }

        try {
            jwt.sign(signer);
        } catch (JOSEException e) {
            log.error("Failed to sign JWT, error was: ", e);
        }
    }

    @Override
    public String getDefaultSignerKeyId() {
        return defaultSignerKeyId;
    }

    private void buildSignersAndVerifiers() {
        for (Map.Entry<String, JWK> jwkEntry : keys.entrySet()) {
            String id = jwkEntry.getKey();
            JWK jwk = jwkEntry.getValue();

            try {
                if (jwk instanceof RSAKey) {
                    // build RSA signers & verifiers

                    if (jwk.isPrivate()) { // only add the signer if there's a private key
                        RSASSASigner signer = new RSASSASigner((RSAKey) jwk);
                        signers.put(id, signer);
                    }

                    RSASSAVerifier verifier = new RSASSAVerifier((RSAKey) jwk);
                    verifiers.put(id, verifier);
                } else if (jwk instanceof ECKey) {
                    // build EC signers & verifiers

                    if (jwk.isPrivate()) {
                        ECDSASigner signer = new ECDSASigner((ECKey) jwk);
                        signers.put(id, signer);
                    }

                    ECDSAVerifier verifier = new ECDSAVerifier((ECKey) jwk);
                    verifiers.put(id, verifier);
                } else if (jwk instanceof OctetSequenceKey) {
                    // build HMAC signers & verifiers

                    if (jwk.isPrivate()) { // technically redundant check because all HMAC keys are private
                        MACSigner signer = new MACSigner((OctetSequenceKey) jwk);
                        signers.put(id, signer);
                    }

                    MACVerifier verifier = new MACVerifier((OctetSequenceKey) jwk);
                    verifiers.put(id, verifier);
                } else {
                    log.warn("Unknown key type: " + jwk);
                }
            } catch (JOSEException e) {
                log.warn("Exception loading signer/verifier", e);
            }
        }

        if (defaultSignerKeyId == null && keys.size() == 1) {
            setDefaultSignerKeyId(keys.keySet().iterator().next());

            Optional<JWK> optionalJWK = keys.values().stream().findFirst();
            optionalJWK.ifPresent(jwk -> {
                setDefaultSigningAlgorithmName(jwk.getAlgorithm().getName());
                defaultAlgorithm = JWSAlgorithm.parse(jwk.getAlgorithm().getName());
            });
        }
    }

}
