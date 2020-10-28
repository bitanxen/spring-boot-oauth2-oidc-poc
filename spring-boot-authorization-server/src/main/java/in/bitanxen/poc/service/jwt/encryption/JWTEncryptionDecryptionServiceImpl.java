package in.bitanxen.poc.service.jwt.encryption;

import com.google.common.base.Strings;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import in.bitanxen.poc.config.bean.JWKSetKeyStore;
import in.bitanxen.poc.util.CommonUtil;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@Log4j2
public class JWTEncryptionDecryptionServiceImpl implements JWTEncryptionDecryptionService {

    private final Map<String, JWEEncrypter> encrypters = new HashMap<>();
    private final Map<String, JWEDecrypter> decrypters = new HashMap<>();
    private Map<String, JWK> keys = new HashMap<>();

    @Setter
    @Getter
    @Value("${sysbean.oauth2.server.config.jwk.enc-key}")
    private String defaultEncryptionKeyId;

    @Setter
    @Getter
    @Value("${sysbean.oauth2.server.config.jwk.dec-key}")
    private String defaultDecryptionKeyId;

    @Setter
    @Getter
    @Value("${sysbean.oauth2.server.config.jwk.encdec-algo}")
    private String defaultSigningAlgorithmName;

    @Setter
    private JWSAlgorithm defaultAlgorithm;

    public JWTEncryptionDecryptionServiceImpl(Map<String, JWK> keys) throws JOSEException {
        this.keys = keys;
        buildEncryptersAndDecrypters();
    }

    @Autowired
    public JWTEncryptionDecryptionServiceImpl(JWKSetKeyStore keyStore) throws JOSEException {
        // convert all keys in the keystore to a map based on key id
        for (JWK key : keyStore.getKeys()) {
            if (!Strings.isNullOrEmpty(key.getKeyID())) {
                this.keys.put(key.getKeyID(), key);
            } else {
                throw new IllegalArgumentException("Tried to load a key from a keystore without a 'kid' field: " + key);
            }
        }
        buildEncryptersAndDecrypters();
        defaultAlgorithm = JWSAlgorithm.parse(defaultSigningAlgorithmName);
    }

    @Override
    public void encryptJwt(JWEObject jwt) {
        if (getDefaultEncryptionKeyId() == null) {
            throw new IllegalStateException("Tried to call default encryption with no default encrypter ID set");
        }

        JWEEncrypter encrypter = encrypters.get(getDefaultEncryptionKeyId());
        try {
            jwt.encrypt(encrypter);
        } catch (JOSEException e) {
            log.error("Failed to encrypt JWT, error was: {}", e.getLocalizedMessage());
        }
    }

    @Override
    public void decryptJwt(JWEObject jwt) {
        if (getDefaultDecryptionKeyId() == null) {
            throw new IllegalStateException("Tried to call default decryption with no default decrypter ID set");
        }

        JWEDecrypter decrypter = decrypters.get(getDefaultDecryptionKeyId());
        try {
            jwt.decrypt(decrypter);
        } catch (JOSEException e) {
            log.error("Failed to decrypt JWT, error was: {}", e.getLocalizedMessage());
        }
    }

    @Override
    public Map<String, JWK> getAllPublicKeys() {
        return CommonUtil.getJWKPublicKeys(keys);
    }

    @Override
    public JWSAlgorithm getDefaultSigningAlgorithm() {
        return defaultAlgorithm;
    }

    @Override
    public Collection<JWEAlgorithm> getAllAlgorithmsSupported() {
        Set<JWEAlgorithm> algs = new HashSet<>();

        for (JWEEncrypter encrypter : encrypters.values()) {
            algs.addAll(encrypter.supportedJWEAlgorithms());
        }

        for (JWEDecrypter decrypter : decrypters.values()) {
            algs.addAll(decrypter.supportedJWEAlgorithms());
        }
        return algs;
    }

    @Override
    public Collection<EncryptionMethod> getAllEncryptionSupported() {
        Set<EncryptionMethod> encs = new HashSet<>();

        for (JWEEncrypter encrypter : encrypters.values()) {
            encs.addAll(encrypter.supportedEncryptionMethods());
        }

        for (JWEDecrypter decrypter : decrypters.values()) {
            encs.addAll(decrypter.supportedEncryptionMethods());
        }
        return encs;
    }

    private void buildEncryptersAndDecrypters() throws JOSEException {
        for (Map.Entry<String, JWK> jwkEntry : keys.entrySet()) {

            String id = jwkEntry.getKey();
            JWK jwk = jwkEntry.getValue();

            if (jwk instanceof RSAKey) {
                // build RSA encrypters and decrypters

                RSAEncrypter encrypter = new RSAEncrypter((RSAKey) jwk); // there should always at least be the public key
                encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
                encrypters.put(id, encrypter);

                if (jwk.isPrivate()) { // we can decrypt!
                    RSADecrypter decrypter = new RSADecrypter((RSAKey) jwk);
                    decrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
                    decrypters.put(id, decrypter);
                } else {
                    log.warn("No private key for key #" + jwk.getKeyID());
                }
            } else if (jwk instanceof ECKey) {
                // build EC Encrypters and decrypters

                ECDHEncrypter encrypter = new ECDHEncrypter((ECKey) jwk);
                encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
                encrypters.put(id, encrypter);

                if (jwk.isPrivate()) { // we can decrypt too
                    ECDHDecrypter decrypter = new ECDHDecrypter((ECKey) jwk);
                    decrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
                    decrypters.put(id, decrypter);
                } else {
                    log.warn("No private key for key # " + jwk.getKeyID());
                }
            } else if (jwk instanceof OctetSequenceKey) {
                // build symmetric encrypters and decrypters

                DirectEncrypter encrypter = new DirectEncrypter((OctetSequenceKey) jwk);
                encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
                DirectDecrypter decrypter = new DirectDecrypter((OctetSequenceKey) jwk);
                decrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

                encrypters.put(id, encrypter);
                decrypters.put(id, decrypter);
            } else {
                log.warn("Unknown key type: " + jwk);
            }
        }

        if(defaultDecryptionKeyId == null && defaultEncryptionKeyId == null && keys.size() == 1) {
            setDefaultDecryptionKeyId(keys.keySet().iterator().next());
            setDefaultEncryptionKeyId(keys.keySet().iterator().next());

            Optional<JWK> optionalJWK = keys.values().stream().findFirst();
            optionalJWK.ifPresent(jwk -> {
                setDefaultSigningAlgorithmName(jwk.getAlgorithm().getName());
                defaultAlgorithm = JWSAlgorithm.parse(jwk.getAlgorithm().getName());
            });
        }
    }
}
