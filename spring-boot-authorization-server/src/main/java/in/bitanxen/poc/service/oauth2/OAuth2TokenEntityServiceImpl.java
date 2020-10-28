package in.bitanxen.poc.service.oauth2;

import com.google.common.base.Strings;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import in.bitanxen.poc.config.bean.ConfigurationProperty;
import in.bitanxen.poc.config.jose.PKCEAlgorithm;
import in.bitanxen.poc.model.approved.ApprovedSite;
import in.bitanxen.poc.model.authholder.AuthenticationHolderEntity;
import in.bitanxen.poc.model.client.ClientEntity;
import in.bitanxen.poc.model.scope.SystemScope;
import in.bitanxen.poc.model.statics.SystemScopeType;
import in.bitanxen.poc.model.token.AccessTokenEntity;
import in.bitanxen.poc.model.token.AccessTokenScope;
import in.bitanxen.poc.model.token.RefreshTokenEntity;
import in.bitanxen.poc.service.auth.AuthenticationHolderService;
import in.bitanxen.poc.service.client.ClientEntityService;
import in.bitanxen.poc.service.jwt.signer.JWTSignerVerifierService;
import in.bitanxen.poc.service.scope.SystemScopeService;
import in.bitanxen.poc.service.token.TokenEntityService;
import in.bitanxen.poc.service.watchlist.ApprovedSiteService;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.stream.Collectors;

import static in.bitanxen.poc.config.openid.ConnectRequestParameters.*;

@Service
@Log4j2
@Transactional
public class OAuth2TokenEntityServiceImpl implements OAuth2TokenEntityService {

    private final ConfigurationProperty configurationProperty;
    private final TokenEntityService tokenEntityService;
    private final AuthenticationHolderService authenticationHolderService;
    private final SystemScopeService systemScopeService;
    private final ApprovedSiteService approvedSiteService;
    private final JWTSignerVerifierService jwtSignerVerifierService;

    @Autowired
    @Lazy
    private ClientEntityService clientEntityService;

    @Autowired
    @Qualifier("connectTokenEnhancer")
    @Lazy
    private TokenEnhancer tokenEnhancer;

    public OAuth2TokenEntityServiceImpl(ConfigurationProperty configurationProperty, TokenEntityService tokenEntityService, AuthenticationHolderService authenticationHolderService,
                                        SystemScopeService systemScopeService, ApprovedSiteService approvedSiteService, JWTSignerVerifierService jwtSignerVerifierService) {
        this.configurationProperty = configurationProperty;
        this.tokenEntityService = tokenEntityService;
        this.authenticationHolderService = authenticationHolderService;
        this.systemScopeService = systemScopeService;
        this.approvedSiteService = approvedSiteService;
        this.jwtSignerVerifierService = jwtSignerVerifierService;
    }

    @Override
    public OAuth2Authentication loadAuthentication(String accessTokenValue) throws AuthenticationException, InvalidTokenException {
        AccessTokenEntity accessToken = clearExpiredAccessToken(tokenEntityService.getAccessTokenByValue(accessTokenValue));

        if (accessToken == null) {
            throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
        }
        return accessToken.getAuthenticationHolder().getAuthentication();
    }

    @Override
    public AccessTokenEntity readAccessToken(String accessTokenValue) {
        AccessTokenEntity accessToken = clearExpiredAccessToken(tokenEntityService.getAccessTokenByValue(accessTokenValue));

        if (accessToken == null) {
            throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
        }
        return accessToken;
    }

    @Override
    public RefreshTokenEntity getRefreshToken(String refreshTokenValue) {
        RefreshTokenEntity refreshToken = tokenEntityService.getRefreshTokenByValue(refreshTokenValue);
        if (refreshToken == null) {
            throw new InvalidTokenException("Refresh token for value " + refreshTokenValue + " was not found");
        }
        return refreshToken;
    }

    @Override
    public void revokeRefreshToken(RefreshTokenEntity refreshToken) {
        tokenEntityService.clearAccessTokensForRefreshToken(refreshToken);
        tokenEntityService.removeRefreshToken(refreshToken);
    }

    @Override
    public void revokeAccessToken(AccessTokenEntity accessToken) {
        tokenEntityService.removeAccessToken(accessToken);
    }

    @Override
    public List<AccessTokenEntity> getAccessTokensForClient(ClientEntity client) {
        return tokenEntityService.getAccessTokensForClient(client);
    }

    @Override
    public List<RefreshTokenEntity> getRefreshTokensForClient(ClientEntity client) {
        return tokenEntityService.getRefreshTokensForClient(client);
    }

    @Override
    public void clearExpiredTokens() {
        Set<AccessTokenEntity> allExpiredAccessTokens = tokenEntityService.getAllExpiredAccessTokens();
        Set<RefreshTokenEntity> allExpiredRefreshTokens = tokenEntityService.getAllExpiredRefreshTokens();
        Collection<AuthenticationHolderEntity> orphanedAuthenticationHolders = authenticationHolderService.getOrphanedAuthenticationHolders();

        // ## TODO: Remove all this
    }

    @Override
    public AccessTokenEntity saveAccessToken(AccessTokenEntity accessToken) {
        AccessTokenEntity newToken = tokenEntityService.saveAccessToken(accessToken);

        if (accessToken.getAdditionalInformation() != null && !accessToken.getAdditionalInformation().isEmpty()) {
            newToken.getAdditionalInformation().putAll(accessToken.getAdditionalInformation());
        }

        return newToken;
    }

    @Override
    public RefreshTokenEntity saveRefreshToken(RefreshTokenEntity refreshToken) {
        return tokenEntityService.saveRefreshToken(refreshToken);
    }

    @Override
    public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {
        if(authentication == null || authentication.getOAuth2Request() == null) {
            throw new AuthenticationCredentialsNotFoundException("No authentication credentials found");
        }

        OAuth2Request request = authentication.getOAuth2Request();

        ClientEntity client = clientEntityService.getClientEntityByClientId(request.getClientId());

        if (client == null) {
            throw new InvalidClientException("Client not found: " + request.getClientId());
        }

        if (request.getExtensions().containsKey(CODE_CHALLENGE)) {
            String challenge = (String) request.getExtensions().get(CODE_CHALLENGE);
            PKCEAlgorithm alg = PKCEAlgorithm.parse((String) request.getExtensions().get(CODE_CHALLENGE_METHOD));

            String verifier = request.getRequestParameters().get(CODE_VERIFIER);

            if (alg.equals(PKCEAlgorithm.plain)) {
                if (!challenge.equals(verifier)) {
                    throw new InvalidRequestException("Code challenge and verifier do not match");
                }
            } else if (alg.equals(PKCEAlgorithm.S256)) {
                try {
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    String hash = Base64URL.encode(digest.digest(verifier.getBytes(StandardCharsets.US_ASCII))).toString();
                    if (!challenge.equals(hash)) {
                        throw new InvalidRequestException("Code challenge and verifier do not match");
                    }
                } catch (NoSuchAlgorithmException e) {
                    log.error("Unknown algorithm for PKCE digest", e);
                }
            }
        }

        AccessTokenEntity token = new AccessTokenEntity();
        token.setClient(client);

        Collection<SystemScope> systemScopes = systemScopeService.fromStrings(request.getScope());
        systemScopes = systemScopeService.removeReservedScopes(systemScopes);
        Set<AccessTokenScope> accessTokenScopes = systemScopes.stream().map(systemScope -> new AccessTokenScope(token, systemScope.getValue())).collect(Collectors.toSet());
        token.setScopes(accessTokenScopes);

        if (client.getAccessTokenValiditySeconds() > 0) {
            LocalDateTime expiration = LocalDateTime.now().plusSeconds(client.getAccessTokenValiditySeconds());
            token.setExpiration(expiration);
        }

        AuthenticationHolderEntity authHolder = new AuthenticationHolderEntity();
        authHolder.setAuthentication(authentication);
        authHolder = authenticationHolderService.save(authHolder);
        token.setAuthenticationHolder(authHolder);

        if (client.isAllowRefresh() && token.getScope().contains(SystemScopeType.OFFLINE_ACCESS.getValue())) {
            RefreshTokenEntity savedRefreshToken = createRefreshToken(client, authHolder);
            token.setRefreshToken(savedRefreshToken);
        }

        OAuth2Request originalAuthRequest = authHolder.getAuthentication().getOAuth2Request();

        if (originalAuthRequest.getExtensions() != null && originalAuthRequest.getExtensions().containsKey("approved_site")) {

            String apId = (String) originalAuthRequest.getExtensions().get("approved_site");
            ApprovedSite ap = approvedSiteService.getById(apId);

            token.setApprovedSite(ap);
        }

        AccessTokenEntity enhancedToken = (AccessTokenEntity) tokenEnhancer.enhance(token, authentication);
        AccessTokenEntity savedToken = saveAccessToken(enhancedToken);

        if (savedToken.getRefreshToken() != null) {
            tokenEntityService.saveRefreshToken(savedToken.getRefreshToken()); // make sure we save any changes that might have been enhanced
        }

        return savedToken;
    }

    @Override
    public OAuth2AccessToken refreshAccessToken(String refreshTokenValue, TokenRequest tokenRequest) throws AuthenticationException {
        if (Strings.isNullOrEmpty(refreshTokenValue)) {
            throw new InvalidTokenException("Invalid refresh token: " + refreshTokenValue);
        }

        RefreshTokenEntity refreshToken = clearExpiredRefreshToken(tokenEntityService.getRefreshTokenByValue(refreshTokenValue));
        if (refreshToken == null) {
            throw new InvalidTokenException("Invalid refresh token: " + refreshTokenValue);
        }

        ClientEntity client = refreshToken.getClient();
        AuthenticationHolderEntity authHolder = refreshToken.getAuthenticationHolder();

        ClientEntity requestingClient = clientEntityService.getClientEntityByClientId(tokenRequest.getClientId());

        if (!client.getClientId().equals(requestingClient.getClientId())) {
            tokenEntityService.removeRefreshToken(refreshToken);
            throw new InvalidClientException("Client does not own the presented refresh token");
        }

        if (!client.isAllowRefresh()) {
            throw new InvalidClientException("Client does not allow refreshing access token!");
        }

        // clear out any access tokens
        if (client.isClearAccessTokensOnRefresh()) {
            tokenEntityService.clearAccessTokensForRefreshToken(refreshToken);
        }

        if (refreshToken.isExpired()) {
            tokenEntityService.removeRefreshToken(refreshToken);
            throw new InvalidTokenException("Expired refresh token: " + refreshTokenValue);
        }

        AccessTokenEntity token = new AccessTokenEntity();

        Set<String> refreshScopesRequested = new HashSet<>(refreshToken.getAuthenticationHolder().getAuthentication().getOAuth2Request().getScope());
        Collection<SystemScope> refreshScopes = systemScopeService.fromStrings(refreshScopesRequested);
        refreshScopes = systemScopeService.removeReservedScopes(refreshScopes);

        Set<String> scopeRequested = tokenRequest.getScope() == null ? new HashSet<String>() : new HashSet<>(tokenRequest.getScope());
        Collection<SystemScope> scope = systemScopeService.fromStrings(scopeRequested);
        scope = systemScopeService.removeReservedScopes(scope);

        if (scope != null && !scope.isEmpty()) {
            // ensure a proper subset of scopes
            if (refreshScopes != null && refreshScopes.containsAll(scope)) {
                Set<AccessTokenScope> accessTokenScopes = scope.stream().map(systemScope -> new AccessTokenScope(token, systemScope.getValue())).collect(Collectors.toSet());
                token.setScopes(accessTokenScopes);
            } else {
                String errorMsg = "Up-scoping is not allowed.";
                log.error(errorMsg);
                throw new InvalidScopeException(errorMsg);
            }
        } else {
            Set<AccessTokenScope> accessTokenScopes = refreshScopes.stream().map(systemScope -> new AccessTokenScope(token, systemScope.getValue())).collect(Collectors.toSet());
            token.setScopes(accessTokenScopes);
        }

        token.setClient(client);

        if (client.getAccessTokenValiditySeconds() > 0) {
            LocalDateTime expiration = LocalDateTime.now().plusSeconds(client.getAccessTokenValiditySeconds());
            token.setExpiration(expiration);
        }

        if (client.isReuseRefreshToken()) {
            token.setRefreshToken(refreshToken);
        } else {
            // otherwise, make a new refresh token
            RefreshTokenEntity newRefresh = createRefreshToken(client, authHolder);
            token.setRefreshToken(newRefresh);

            // clean up the old refresh token
            //tokenEntityService.removeRefreshToken(refreshToken);
            refreshToken.setExpiration(LocalDateTime.now());
        }

        token.setAuthenticationHolder(authHolder);
        AccessTokenEntity enhanceToken = (AccessTokenEntity) tokenEnhancer.enhance(token, authHolder.getAuthentication());
        return tokenEntityService.saveAccessToken(enhanceToken);
    }

    @Override
    public AccessTokenEntity getAccessToken(OAuth2Authentication authentication) {
        return null;
    }

    @Override
    public AccessTokenEntity getAccessTokenById(String id) {
        return tokenEntityService.getAccessTokenById(id);
    }

    @Override
    public RefreshTokenEntity getRefreshTokenById(String id) {
        return tokenEntityService.getRefreshTokenById(id);
    }

    @Override
    public Set<AccessTokenEntity> getAllAccessTokensForUser(String name) {
        return tokenEntityService.getAccessTokensByUserName(name);
    }

    @Override
    public Set<RefreshTokenEntity> getAllRefreshTokensForUser(String name) {
        return tokenEntityService.getRefreshTokensByUserName(name);
    }

    @Override
    public AccessTokenEntity getRegistrationAccessTokenForClient(ClientEntity client) {
        List<AccessTokenEntity> allTokens = getAccessTokensForClient(client);

        for (AccessTokenEntity token : allTokens) {
            if ((token.getScope().contains(SystemScopeType.REGISTRATION_TOKEN_SCOPE.getValue()) || token.getScope().contains(SystemScopeType.RESOURCE_TOKEN_SCOPE.getValue()))
                    && token.getScope().size() == 1) {
                // if it only has the registration scope, then it's a registration token
                return token;
            }
        }

        return null;
    }

    private RefreshTokenEntity createRefreshToken(ClientEntity client, AuthenticationHolderEntity authHolder) {
        OAuth2Authentication authentication = authHolder.getAuthentication();
        RefreshTokenEntity refreshToken = new RefreshTokenEntity(); //refreshTokenFactory.createNewRefreshToken();
        JWTClaimsSet.Builder refreshClaims = new JWTClaimsSet.Builder();

        if (client.getRefreshTokenValiditySeconds() > 0) {
            LocalDateTime expiration = LocalDateTime.now().plusSeconds(client.getRefreshTokenValiditySeconds());
            refreshToken.setExpiration(expiration);
            refreshClaims.expirationTime(Date.from(expiration.atZone(ZoneId.systemDefault()).toInstant()));
        }

        refreshClaims.claim("azp", client.getClientId());
        refreshClaims.issueTime(new Date());
        refreshClaims.subject(authentication.getName());
        refreshClaims.jwtID(UUID.randomUUID().toString());
        refreshClaims.issuer(configurationProperty.getIssuer());
        JWTClaimsSet claims = refreshClaims.build();

        JWSAlgorithm signingAlg = jwtSignerVerifierService.getDefaultSigningAlgorithm();

        JWSHeader header = new JWSHeader.Builder(signingAlg).keyID(jwtSignerVerifierService.getDefaultSignerKeyId()).build();
        SignedJWT signed = new SignedJWT(header, claims);
        jwtSignerVerifierService.signJwt(signed, signingAlg);

        refreshToken.setJwt(signed);

        refreshToken.setAuthenticationHolder(authHolder);
        refreshToken.setClient(client);

        return tokenEntityService.saveRefreshToken(refreshToken);
    }

    private AccessTokenEntity clearExpiredAccessToken(AccessTokenEntity token) {
        if (token == null) {
            return null;
        } else if (token.isExpired()) {
            log.debug("Clearing expired access token: " + token.getValue());
            revokeAccessToken(token);
            return null;
        } else {
            return token;
        }
    }

    private RefreshTokenEntity clearExpiredRefreshToken(RefreshTokenEntity token) {
        if (token == null) {
            return null;
        } else if (token.isExpired()) {
            // immediately revoke expired token
            log.debug("Clearing expired refresh token: " + token.getValue());
            revokeRefreshToken(token);
            return null;
        } else {
            return token;
        }
    }
}
