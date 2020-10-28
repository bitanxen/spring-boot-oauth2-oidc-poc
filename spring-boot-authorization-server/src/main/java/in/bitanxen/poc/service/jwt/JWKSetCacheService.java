package in.bitanxen.poc.service.jwt;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.UncheckedExecutionException;
import com.google.gson.JsonParseException;
import com.nimbusds.jose.jwk.JWKSet;
import in.bitanxen.poc.config.bean.JWKSetKeyStore;
import in.bitanxen.poc.service.jwt.encryption.JWTEncryptionDecryptionService;
import in.bitanxen.poc.service.jwt.encryption.JWTEncryptionDecryptionServiceImpl;
import in.bitanxen.poc.service.jwt.signer.JWTSignerVerifierService;
import in.bitanxen.poc.service.jwt.signer.JWTSignerVerifierServiceImpl;
import lombok.extern.log4j.Log4j2;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

@Log4j2
@Service
public class JWKSetCacheService {

    private final LoadingCache<String, JWTSignerVerifierService> validators;
    private final LoadingCache<String, JWTEncryptionDecryptionService> encrypters;

    public JWKSetCacheService() {
        this.validators = CacheBuilder.newBuilder()
                .expireAfterWrite(1, TimeUnit.HOURS) // expires 1 hour after fetch
                .maximumSize(100)
                .build(new JWKSetVerifierFetcher(HttpClientBuilder.create().useSystemProperties().build()));
        this.encrypters = CacheBuilder.newBuilder()
                .expireAfterWrite(1, TimeUnit.HOURS) // expires 1 hour after fetch
                .maximumSize(100)
                .build(new JWKSetEncryptorFetcher(HttpClientBuilder.create().useSystemProperties().build()));
    }

    public JWTSignerVerifierService getValidator(String jwksUri) {
        try {
            return validators.get(jwksUri);
        } catch (UncheckedExecutionException | ExecutionException e) {
            log.warn("Couldn't load JWK Set from " + jwksUri + ": " + e.getMessage());
            return null;
        }
    }

    public JWTEncryptionDecryptionService getEncrypter(String jwksUri) {
        try {
            return encrypters.get(jwksUri);
        } catch (UncheckedExecutionException | ExecutionException e) {
            log.warn("Couldn't load JWK Set from " + jwksUri + ": " + e.getMessage());
            return null;
        }
    }

    private static class JWKSetVerifierFetcher extends CacheLoader<String, JWTSignerVerifierService> {
        private final RestTemplate restTemplate;

        JWKSetVerifierFetcher(HttpClient httpClient) {
            HttpComponentsClientHttpRequestFactory httpFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
            this.restTemplate = new RestTemplate(httpFactory);
        }

        /**
         * Load the JWK Set and build the appropriate signing service.
         */
        @Override
        public JWTSignerVerifierService load(String key) throws Exception {
            String jsonString = restTemplate.getForObject(key, String.class);
            JWKSet jwkSet = JWKSet.parse(jsonString);
            JWKSetKeyStore keyStore = new JWKSetKeyStore(jwkSet);
            return new JWTSignerVerifierServiceImpl(keyStore);
        }
    }

    private static class JWKSetEncryptorFetcher extends CacheLoader<String, JWTEncryptionDecryptionService> {
        private final RestTemplate restTemplate;

        public JWKSetEncryptorFetcher(HttpClient httpClient) {
            HttpComponentsClientHttpRequestFactory httpFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
            this.restTemplate = new RestTemplate(httpFactory);
        }

        /* (non-Javadoc)
         * @see com.google.common.cache.CacheLoader#load(java.lang.Object)
         */
        @Override
        public JWTEncryptionDecryptionService load(String key) throws Exception {
            try {
                String jsonString = restTemplate.getForObject(key, String.class);
                JWKSet jwkSet = JWKSet.parse(jsonString);
                JWKSetKeyStore keyStore = new JWKSetKeyStore(jwkSet);
                return new JWTEncryptionDecryptionServiceImpl(keyStore);
            } catch (JsonParseException | RestClientException e) {
                log.error("Unable to load JWK Set : {}", e.getLocalizedMessage());
                throw new IllegalArgumentException("Unable to load JWK Set");
            }
        }
    }
}
