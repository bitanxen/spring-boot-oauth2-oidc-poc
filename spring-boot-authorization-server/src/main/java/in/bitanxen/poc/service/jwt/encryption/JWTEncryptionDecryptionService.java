package in.bitanxen.poc.service.jwt.encryption;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;

import java.util.Collection;
import java.util.Map;

public interface JWTEncryptionDecryptionService {
    void encryptJwt(JWEObject jwt);
    void decryptJwt(JWEObject jwt);
    Map<String, JWK> getAllPublicKeys();
    JWSAlgorithm getDefaultSigningAlgorithm();
    Collection<JWEAlgorithm> getAllAlgorithmsSupported();
    Collection<EncryptionMethod> getAllEncryptionSupported();
}
