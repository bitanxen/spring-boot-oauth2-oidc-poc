package in.bitanxen.poc.service.assertion;

import com.google.common.base.Strings;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import in.bitanxen.poc.config.bean.ConfigurationProperty;
import in.bitanxen.poc.service.jwt.JWKSetCacheService;
import in.bitanxen.poc.service.jwt.signer.JWTSignerVerifierService;
import in.bitanxen.poc.service.watchlist.BlackListService;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

import java.text.ParseException;

@Service
@Log4j2
public class AssertionValidatorServiceImpl implements AssertionValidatorService {

    private final BlackListService blackListService;
    private final ConfigurationProperty configurationProperty;
    private final JWKSetCacheService jwkSetCacheService;

    public AssertionValidatorServiceImpl(BlackListService blackListService, ConfigurationProperty configurationProperty, JWKSetCacheService jwkSetCacheService) {
        this.blackListService = blackListService;
        this.configurationProperty = configurationProperty;
        this.jwkSetCacheService = jwkSetCacheService;
    }

    @Override
    public boolean isValid(JWT assertion) {
        if (!(assertion instanceof SignedJWT)) {
            return false;
        }

        JWTClaimsSet claims;
        try {
            claims = assertion.getJWTClaimsSet();
        } catch (ParseException e) {
            log.debug("Invalid assertion claims");
            return false;
        }

        if (Strings.isNullOrEmpty(claims.getIssuer())) {
            log.debug("No issuer for assertion, rejecting");
            return false;
        }

        if (blackListService.isSiteBlacklisted(claims.getIssuer())) {
            log.debug("Issuer is not in whitelist, rejecting");
            return false;
        }

        String jwksUri = configurationProperty.getJwkUri();
        JWTSignerVerifierService validator = jwkSetCacheService.getValidator(jwksUri);

        return validator.validateSignature((SignedJWT) assertion);
    }
}
