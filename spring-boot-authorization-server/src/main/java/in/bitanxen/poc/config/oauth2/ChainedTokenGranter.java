package in.bitanxen.poc.config.oauth2;

import com.google.common.collect.Sets;
import in.bitanxen.poc.model.token.AccessTokenEntity;
import in.bitanxen.poc.service.client.ClientEntityService;
import in.bitanxen.poc.service.oauth2.OAuth2TokenEntityService;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
public class ChainedTokenGranter extends AbstractTokenGranter {

    public static final String GRANT_TYPE = "urn:ietf:params:oauth:grant_type:redelegate";
    private OAuth2TokenEntityService tokenServices;

    protected ChainedTokenGranter(OAuth2TokenEntityService tokenServices, ClientEntityService clientService, OAuth2RequestFactory requestFactory) {
        super(tokenServices, clientService, requestFactory, GRANT_TYPE);
        this.tokenServices = tokenServices;
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        String incomingTokenValue = tokenRequest.getRequestParameters().get("token");
        AccessTokenEntity accessTokenEntity = tokenServices.readAccessToken(incomingTokenValue);

        Set<String> approvedScopes = accessTokenEntity.getScope();
        Set<String> requestedScopes = tokenRequest.getScope();

        if (requestedScopes == null) {
            requestedScopes = new HashSet<>();
        }

        if (client.getScope().equals(requestedScopes)) {
            requestedScopes = new HashSet<>();
        }

        if (approvedScopes.containsAll(requestedScopes)) {
            if (requestedScopes.isEmpty()) {
                // if there are no scopes, inherit the original scopes from the token
                tokenRequest.setScope(approvedScopes);
            } else {
                // if scopes were asked for, give only the subset of scopes requested
                // this allows safe downscoping
                tokenRequest.setScope(Sets.intersection(requestedScopes, approvedScopes));
            }

            // NOTE: don't revoke the existing access token
            // create a new access token
            return new OAuth2Authentication(getRequestFactory().createOAuth2Request(client, tokenRequest), accessTokenEntity.getAuthenticationHolder().getAuthentication().getUserAuthentication());

        } else {
            throw new InvalidScopeException("Invalid scope requested in chained request", approvedScopes);
        }
    }
}
