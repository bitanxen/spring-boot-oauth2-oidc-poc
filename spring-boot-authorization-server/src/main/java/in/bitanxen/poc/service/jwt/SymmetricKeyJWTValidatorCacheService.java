package in.bitanxen.poc.service.jwt;

import com.google.common.base.Strings;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.ImmutableMap;
import com.google.common.util.concurrent.UncheckedExecutionException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64URL;
import in.bitanxen.poc.dto.client.ClientEntityDTO;
import in.bitanxen.poc.service.jwt.signer.JWTSignerVerifierService;
import in.bitanxen.poc.service.jwt.signer.JWTSignerVerifierServiceImpl;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

@Service
@Log4j2
public class SymmetricKeyJWTValidatorCacheService {

    private final LoadingCache<String, JWTSignerVerifierService> validators;

    public SymmetricKeyJWTValidatorCacheService() {
        validators = CacheBuilder.newBuilder()
                .expireAfterAccess(24, TimeUnit.HOURS)
                .maximumSize(100)
                .build(new SymmetricValidatorBuilder());
    }

    public JWTSignerVerifierService getSymmetricValidtor(ClientEntityDTO client) {

        if (client == null) {
            log.error("Couldn't create symmetric validator for null client");
            return null;
        }

        if (Strings.isNullOrEmpty(client.getClientSecret())) {
            log.error("Couldn't create symmetric validator for client " + client.getClientId() + " without a client secret");
            return null;
        }

        try {
            return validators.get(client.getClientSecret());
        } catch (UncheckedExecutionException | ExecutionException ue) {
            log.error("Problem loading client validator", ue);
            return null;
        }
    }

    public static class SymmetricValidatorBuilder extends CacheLoader<String, JWTSignerVerifierService> {
        @Override
        public JWTSignerVerifierService load(String key) {

            String id = "SYMMETRIC-KEY";
            JWK jwk = new OctetSequenceKey.Builder(Base64URL.encode(key))
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(id)
                    .build();
            Map<String, JWK> keys = ImmutableMap.of(id, jwk);
            return new JWTSignerVerifierServiceImpl(keys);
        }

    }
}
