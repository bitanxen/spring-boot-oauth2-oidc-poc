package in.bitanxen.poc.dto.client;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import in.bitanxen.poc.model.statics.*;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Getter
@Setter
@Builder
public class ClientEntityDTO implements ClientDetails {
    private String id;
    private String clientId;
    private String clientSecret;
    private String clientName;
    private Set<ClientRedirectDTO> redirectUris;
    private String clientUri;
    private Set<ClientContactDTO> contacts;
    private String logoUri;
    private String tosUri;
    private AuthMethod tokenEndpointAuthMethod;
    private Set<ClientScopeDTO> clientScopes;
    private Set<ClientGrantTypeDTO> grantTypes;
    private Set<ClientResponseTypeDTO> responseTypes;
    private String policyUri;
    private String jwksUri;
    private JWKSet jwks;
    private String softwareId;
    private String softwareVersion;
    private AppType applicationType;
    private String sectorIdentifierUri;
    private SubjectType subjectType;
    private JWSAlgorithm requestObjectSigningAlg;
    private JWSAlgorithm userInfoSignedResponseAlg;
    private JWEAlgorithm userInfoEncryptedResponseAlg;
    private EncryptionMethod userInfoEncryptedResponseEnc;
    private JWSAlgorithm idTokenSignedResponseAlg;
    private JWEAlgorithm idTokenEncryptedResponseAlg;
    private EncryptionMethod idTokenEncryptedResponseEnc;
    private JWSAlgorithm tokenEndpointAuthSigningAlg;
    private int defaultMaxAge;
    private boolean requireAuthTime;
    private Set<ClientACRValueDTO> defaultACRvalues;
    private String initiateLoginUri;
    private Set<ClientLogoutRedirectDTO> postLogoutRedirectUris;
    private Set<ClientRequestURIDTO> requestUris;
    private Set<ClientAuthorityDTO> authorities;
    private int accessTokenValiditySeconds;
    private int refreshTokenValiditySeconds;
    private Set<ClientResourceIDDTO> resourceIds;
    private String clientDescription;
    private boolean reuseRefreshToken;
    private boolean dynamicallyRegistered;
    private boolean allowIntrospection;
    private int idTokenValiditySeconds;
    private LocalDateTime createdAt;
    private boolean clearAccessTokensOnRefresh;
    private int deviceCodeValiditySeconds;
    private Set<ClientClaimsRedirectURIDTO> claimsRedirectUris;
    private String softwareStatement;
    private String codeChallengeMethod;

    @Override
    public String getClientId() {
        return clientId;
    }

    @Override
    public Set<String> getResourceIds() {
        return resourceIds.stream().map(ClientResourceIDDTO::getResourceId).collect(Collectors.toSet());
    }

    @Override
    public boolean isSecretRequired() {
        return getTokenEndpointAuthMethod() != null &&
                (getTokenEndpointAuthMethod().equals(AuthMethod.SECRET_BASIC) || getTokenEndpointAuthMethod().equals(AuthMethod.SECRET_POST) || getTokenEndpointAuthMethod().equals(AuthMethod.SECRET_JWT));
    }

    @Override
    public boolean isScoped() {
        return getScope() != null && !getScope().isEmpty();
    }

    @Override
    public Set<String> getScope() {
        if(clientScopes == null || clientScopes.isEmpty()) {
            return new HashSet<>();
        }
        return clientScopes.stream().map(ClientScopeDTO::getScope).collect(Collectors.toSet());
    }

    @Override
    public Set<String> getAuthorizedGrantTypes() {
        if(grantTypes == null || grantTypes.isEmpty()) {
            return new HashSet<>();
        }
        return grantTypes.stream().map(clientGrantTypeDTO -> clientGrantTypeDTO.getGrantType().getType()).collect(Collectors.toSet());
    }

    @Override
    public Set<String> getRegisteredRedirectUri() {
        if(redirectUris == null || redirectUris.isEmpty()) {
            return new HashSet<>();
        }
        return redirectUris.stream().map(ClientRedirectDTO::getRedirectUri).collect(Collectors.toSet());
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        if(authorities == null || authorities.isEmpty()) {
            return new HashSet<>();
        }
        return authorities.stream().map(ClientAuthorityDTO::getAuthority).collect(Collectors.toSet());
    }

    @Override
    public boolean isAutoApprove(String scope) {
        return false;
    }

    @Override
    public Map<String, Object> getAdditionalInformation() {
        return new HashMap<>();
    }

    public Set<String> getRegisteredResponseTypes() {
        return responseTypes.stream().map(clientResponseTypeDTO -> clientResponseTypeDTO.getResponseType().getType()).collect(Collectors.toSet());
    }

    @Override
    public Integer getAccessTokenValiditySeconds() {
        return accessTokenValiditySeconds;
    }

    @Override
    public Integer getRefreshTokenValiditySeconds() {
        return refreshTokenValiditySeconds;
    }

    public boolean hasResponseType(ResponseType responseType) {
        if(responseTypes == null || responseTypes.isEmpty()) {
            return false;
        }
        Optional<ClientResponseTypeDTO> clientResponseTypeOptional = responseTypes.stream().filter(r -> r.getResponseType().equals(responseType)).findFirst();
        return clientResponseTypeOptional.isPresent();
    }

    public boolean hasResponseType(String responseTypeStr) {
        ResponseType responseType = ResponseType.getResponseType(responseTypeStr);
        return hasResponseType(responseType);
    }

    public boolean hasGrantType(GrantType grantType) {
        if(grantTypes == null || grantTypes.isEmpty()) {
            return false;
        }
        Optional<ClientGrantTypeDTO> clientGrantTypeOptional = grantTypes.stream().filter(r -> r.getGrantType().equals(grantType)).findFirst();
        return clientGrantTypeOptional.isPresent();
    }

    public boolean hasGrantType(String grantTypeStr) {
        GrantType grantType = GrantType.getGrantType(grantTypeStr);
        return hasGrantType(grantType);
    }

    public boolean hasScope(String targetScope) {
        Optional<ClientScopeDTO> clientScopeOptional = clientScopes.stream().filter(r -> r.getScope().equals(targetScope)).findFirst();
        return clientScopeOptional.isPresent();
    }

    public boolean isAllowRefresh() {
        return hasGrantType(GrantType.REFRESH_TOKEN);
    }
}
