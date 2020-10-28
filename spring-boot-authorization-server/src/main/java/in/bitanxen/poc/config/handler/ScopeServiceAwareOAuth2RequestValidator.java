package in.bitanxen.poc.config.handler;

import in.bitanxen.poc.service.scope.SystemScopeService;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class ScopeServiceAwareOAuth2RequestValidator implements OAuth2RequestValidator {

    private final SystemScopeService systemScopeService;

    public ScopeServiceAwareOAuth2RequestValidator(SystemScopeService systemScopeService) {
        this.systemScopeService = systemScopeService;
    }

    private void validateScope(Set<String> requestedScopes, Set<String> clientScopes) throws InvalidScopeException {
        if (requestedScopes != null && !requestedScopes.isEmpty()) {
            if (clientScopes != null && !clientScopes.isEmpty()) {
                if (!systemScopeService.scopesMatch(clientScopes, requestedScopes)) {
                    throw new InvalidScopeException("Invalid scope; requested:" + requestedScopes, clientScopes);
                }
            }
        }
    }

    @Override
    public void validateScope(AuthorizationRequest authorizationRequest, ClientDetails client) throws InvalidScopeException {
        validateScope(authorizationRequest.getScope(), client.getScope());
    }

    @Override
    public void validateScope(TokenRequest tokenRequest, ClientDetails client) throws InvalidScopeException {
        validateScope(tokenRequest.getScope(), client.getScope());
    }
}
