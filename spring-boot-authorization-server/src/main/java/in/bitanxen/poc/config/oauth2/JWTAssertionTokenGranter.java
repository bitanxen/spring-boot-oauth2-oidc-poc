package in.bitanxen.poc.config.oauth2;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import in.bitanxen.poc.config.openid.JWTBearerAssertionAuthenticationToken;
import in.bitanxen.poc.service.assertion.AssertionValidatorService;
import in.bitanxen.poc.service.client.ClientEntityService;
import in.bitanxen.poc.service.oauth2.OAuth2RequestService;
import in.bitanxen.poc.service.oauth2.OAuth2TokenEntityService;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.stereotype.Component;

@Component
@Log4j2
public class JWTAssertionTokenGranter extends AbstractTokenGranter {

    private static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    private final AssertionValidatorService assertionValidator;
    private final OAuth2RequestService createOAuth2Request;

    protected JWTAssertionTokenGranter(OAuth2TokenEntityService tokenServices, ClientEntityService clientService, OAuth2RequestFactory requestFactory,
                                       AssertionValidatorService assertionValidator, OAuth2RequestService createOAuth2Request) {
        super(tokenServices, clientService, requestFactory, GRANT_TYPE);
        this.assertionValidator = assertionValidator;
        this.createOAuth2Request = createOAuth2Request;
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        try{
            String incomingAssertionValue = tokenRequest.getRequestParameters().get("assertion");
            JWT assertion = JWTParser.parse(incomingAssertionValue);

            if (assertionValidator.isValid(assertion)) {
                // our validator says it's OK, time to make a token from it
                // the real work happens in the assertion factory and the token services
                return new OAuth2Authentication(createOAuth2Request.createOAuth2Request(client, tokenRequest, assertion),
                        new JWTBearerAssertionAuthenticationToken(assertion, client.getAuthorities()));

            } else {
                logger.warn("Incoming assertion did not pass validator, rejecting");
                return null;
            }
        } catch (Exception e) {
            log.warn("Unable to parse incoming JWT assertion");
        }
        return null;
    }
}
