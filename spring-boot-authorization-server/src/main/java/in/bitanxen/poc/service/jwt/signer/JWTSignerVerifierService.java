package in.bitanxen.poc.service.jwt.signer;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;

import java.util.Collection;
import java.util.Map;

public interface JWTSignerVerifierService {
    Map<String, JWK> getAllPublicKeys();
    boolean validateSignature(SignedJWT jwtString);
    void signJwt(SignedJWT jwt);
    JWSAlgorithm getDefaultSigningAlgorithm();
    Collection<JWSAlgorithm> getAllSigningAlgsSupported();
    void signJwt(SignedJWT jwt, JWSAlgorithm alg);
    String getDefaultSignerKeyId();
}
