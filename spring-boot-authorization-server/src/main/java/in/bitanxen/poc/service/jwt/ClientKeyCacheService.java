package in.bitanxen.poc.service.jwt;

import com.google.common.base.Strings;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.UncheckedExecutionException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import in.bitanxen.poc.config.bean.JWKSetKeyStore;
import in.bitanxen.poc.dto.client.ClientEntityDTO;
import in.bitanxen.poc.service.jwt.encryption.JWTEncryptionDecryptionService;
import in.bitanxen.poc.service.jwt.encryption.JWTEncryptionDecryptionServiceImpl;
import in.bitanxen.poc.service.jwt.signer.JWTSignerVerifierService;
import in.bitanxen.poc.service.jwt.signer.JWTSignerVerifierServiceImpl;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

@Log4j2
@Service
public class ClientKeyCacheService {

    private final JWKSetCacheService jwkSetCacheService;
    private final SymmetricKeyJWTValidatorCacheService symmetricKeyJWTValidatorCacheService;

    private final LoadingCache<JWKSet, JWTSignerVerifierService> jwksValidators;
    private final LoadingCache<JWKSet, JWTEncryptionDecryptionService> jwksEncrypters;

    public ClientKeyCacheService(JWKSetCacheService jwkSetCacheService, SymmetricKeyJWTValidatorCacheService symmetricKeyJWTValidatorCacheService) {
        this.jwkSetCacheService = jwkSetCacheService;
        this.symmetricKeyJWTValidatorCacheService = symmetricKeyJWTValidatorCacheService;
        this.jwksValidators = CacheBuilder.newBuilder()
                .expireAfterWrite(1, TimeUnit.HOURS) // expires 1 hour after fetch
                .maximumSize(100)
                .build(new JWKSetVerifierBuilder());
        this.jwksEncrypters = CacheBuilder.newBuilder()
                .expireAfterWrite(1, TimeUnit.HOURS) // expires 1 hour after fetch
                .maximumSize(100)
                .build(new JWKSetEncryptorBuilder());
    }

    public JWTSignerVerifierService getValidator(ClientEntityDTO client, JWSAlgorithm alg) {

        try {
            if (alg.equals(JWSAlgorithm.RS256)
                    || alg.equals(JWSAlgorithm.RS384)
                    || alg.equals(JWSAlgorithm.RS512)
                    || alg.equals(JWSAlgorithm.ES256)
                    || alg.equals(JWSAlgorithm.ES384)
                    || alg.equals(JWSAlgorithm.ES512)
                    || alg.equals(JWSAlgorithm.PS256)
                    || alg.equals(JWSAlgorithm.PS384)
                    || alg.equals(JWSAlgorithm.PS512)) {
                if (client.getJwks() != null) {
                    return jwksValidators.get(client.getJwks());
                } else if (!Strings.isNullOrEmpty(client.getJwksUri())) {
                    return jwkSetCacheService.getValidator(client.getJwksUri());
                } else {
                    return null;
                }

            } else if (alg.equals(JWSAlgorithm.HS256)
                    || alg.equals(JWSAlgorithm.HS384)
                    || alg.equals(JWSAlgorithm.HS512)) {
                return symmetricKeyJWTValidatorCacheService.getSymmetricValidtor(client);
            } else {
                return null;
            }
        } catch (UncheckedExecutionException | ExecutionException e) {
            log.error("Problem loading client validator", e);
            return null;
        }

    }

    public JWTEncryptionDecryptionService getEncrypter(ClientEntityDTO client) {

        try {
            if (client.getJwks() != null) {
                return jwksEncrypters.get(client.getJwks());
            } else if (!Strings.isNullOrEmpty(client.getJwksUri())) {
                return jwkSetCacheService.getEncrypter(client.getJwksUri());
            } else {
                return null;
            }
        } catch (UncheckedExecutionException | ExecutionException e) {
            log.error("Problem loading client encrypter", e);
            return null;
        }

    }

    private static class JWKSetEncryptorBuilder extends CacheLoader<JWKSet, JWTEncryptionDecryptionService> {
        @Override
        public JWTEncryptionDecryptionService load(JWKSet key) throws Exception {
            return new JWTEncryptionDecryptionServiceImpl(new JWKSetKeyStore(key));
        }

    }

    private static class JWKSetVerifierBuilder extends CacheLoader<JWKSet, JWTSignerVerifierService> {
        @Override
        public JWTSignerVerifierService load(JWKSet key) throws Exception {
            return new JWTSignerVerifierServiceImpl(new JWKSetKeyStore(key));
        }

    }
}
