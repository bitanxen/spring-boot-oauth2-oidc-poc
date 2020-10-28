package in.bitanxen.poc.model.client;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWT;
import in.bitanxen.poc.config.jose.PKCEAlgorithm;
import in.bitanxen.poc.model.converter.*;
import in.bitanxen.poc.model.statics.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.*;

/**
* Defined By IETF: OAuth 2.0 Dynamic Client Registration Protocol
* https://tools.ietf.org/html/rfc7591
*
* Defined By OPENID: OpenID Connect Dynamic Client Registration 1.0
* https://openid.net/specs/openid-connect-registration-1_0.html
*
* @author Bitan Biswas
 */

@Getter
@Setter
@NoArgsConstructor
@Entity(name = "TB_CLIENT")
public class ClientEntity {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "CLIENT_ENTITY_ID", nullable = false, unique = true)
    private String id;

    @Column(name = "CLIENT_ID", length = 10, nullable = false, unique = true)
    private String clientId;

    @Column(name = "CLIENT_SECRET", length = 500, nullable = false)
    private String clientSecret;

    @Column(name = "CLIENT_NAME", length = 25, nullable = false)
    private String clientName;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "clientEntity")
    private Set<ClientRedirect> redirectUris = new HashSet<>();

    @Column(name = "CLIENT_URI", length = 1000, nullable = false)
    private String clientUri;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "clientEntity")
    private Set<ClientContact> contacts = new HashSet<>();

    @Column(name = "LOGO_URI", length = 1000)
    private String logoUri;

    @Column(name = "TOS_URI", length = 1000)
    private String tosUri;

    @Enumerated(EnumType.STRING)
    @Column(name="AUTHENTICATION_TYPE", nullable = false)
    private AuthMethod tokenEndpointAuthMethod = AuthMethod.SECRET_BASIC;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "clientEntity")
    private Set<ClientScope> clientScopes = new HashSet<>();

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "clientEntity")
    private Set<ClientGrantType> grantTypes = new HashSet<>();

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "clientEntity")
    private Set<ClientResponseType> responseTypes = new HashSet<>();

    @Column(name = "POLICY_URI", length = 1000)
    private String policyUri;

    @Column(name = "JWKS_URI", length = 1000)
    private String jwksUri;

    @Lob
    @Column(name = "JWK_SET")
    @Convert(converter = JWKSetStringConverter.class)
    private JWKSet jwks;

    @Column(name = "SOFTWARE_ID", length = 200)
    private String softwareId;

    @Column(name = "SOFTWARE_VERSION", length = 10)
    private String softwareVersion;

    @Enumerated(EnumType.STRING)
    @Column(name="APPLICATION_TYPE", nullable = false)
    private AppType applicationType;

    @Column(name = "SECTOR_IDENTIFIER_URI", length = 1000)
    private String sectorIdentifierUri;

    @Enumerated(EnumType.STRING)
    @Column(name="SUBJECT_TYPE")
    private SubjectType subjectType;

    @Lob
    @Column(name = "REQUEST_OBJECT_SIGN_ALGO")
    @Convert(converter = JWSAlgorithmStringConverter.class)
    private JWSAlgorithm requestObjectSigningAlg;

    @Lob
    @Column(name = "USERINFO_SIGN_RESP_ALGO")
    @Convert(converter = JWSAlgorithmStringConverter.class)
    private JWSAlgorithm userInfoSignedResponseAlg;

    @Lob
    @Column(name = "USERINFO_ENC_RESP_ALGO")
    @Convert(converter = JWEAlgorithmStringConverter.class)
    private JWEAlgorithm userInfoEncryptedResponseAlg;

    @Lob
    @Column(name = "USERINFO_ENC_RESP_ENC")
    @Convert(converter = JWEEncryptionMethodStringConverter.class)
    private EncryptionMethod userInfoEncryptedResponseEnc;

    @Lob
    @Column(name = "ID_TOKEN_SIGN_RESP_ALGO")
    @Convert(converter = JWSAlgorithmStringConverter.class)
    private JWSAlgorithm idTokenSignedResponseAlg;

    @Lob
    @Column(name = "ID_TOKEN_ENC_RESP_ALGO")
    @Convert(converter = JWEAlgorithmStringConverter.class)
    private JWEAlgorithm idTokenEncryptedResponseAlg;

    @Lob
    @Column(name = "ID_TOKEN_ENC_RESP_ENC")
    @Convert(converter = JWEEncryptionMethodStringConverter.class)
    private EncryptionMethod idTokenEncryptedResponseEnc;

    @Lob
    @Column(name = "TOKEN_ENDPOINT_AUTH_SIGN_ALGO")
    @Convert(converter = JWSAlgorithmStringConverter.class)
    private JWSAlgorithm tokenEndpointAuthSigningAlg;

    @Column(name = "DEFAULT_MAX_AGE")
    private int defaultMaxAge;

    @Column(name = "IS_REQUIRE_AUTH_TIME")
    @Convert(converter = BooleanToStringConverter.class)
    private boolean requireAuthTime;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "clientEntity")
    private Set<ClientACRValue> defaultACRvalues = new HashSet<>();

    @Column(name = "INITIATE_LOGIN_URL", length = 1000)
    private String initiateLoginUri;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "clientEntity")
    private Set<ClientLogoutRedirect> postLogoutRedirectUris = new HashSet<>();

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "clientEntity")
    private Set<ClientRequest> requestUris = new HashSet<>();

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "clientEntity")
    private Set<ClientGrantedAuthority> authorities = new HashSet<>();

    @Column(name = "ACCESS_TOKEN_VALIDITY_SEC")
    private int accessTokenValiditySeconds;

    @Column(name = "REFRESH_TOKEN_VALIDITY_SEC")
    private int refreshTokenValiditySeconds;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "clientEntity")
    private Set<ClientResource> resourceIds = new HashSet<>();

    @Transient
    private Map<String, Object> additionalInformation = new HashMap<>();

    @Lob
    @Column(name = "CLIENT_DESCRIPTION")
    private String clientDescription;

    @Column(name = "IS_REUSE_REFRESH_TOKEN")
    @Convert(converter = BooleanToStringConverter.class)
    private boolean reuseRefreshToken;

    @Column(name = "IS_DYNAMICALLY_REGISTERED")
    @Convert(converter = BooleanToStringConverter.class)
    private boolean dynamicallyRegistered;

    @Column(name = "IS_ALLOWED_INTROSECPTION")
    @Convert(converter = BooleanToStringConverter.class)
    private boolean allowIntrospection;

    @Column(name = "ID_TOKEN_VALIDITY_SEC")
    private int idTokenValiditySeconds;

    @Column(name = "CREATED_AT")
    @Convert(converter = LocalDateTimeAttributeConverter.class)
    private LocalDateTime createdAt;

    @Column(name = "IS_CLEAR_ACCESS_TOKEN")
    @Convert(converter = BooleanToStringConverter.class)
    private boolean clearAccessTokensOnRefresh;

    @Column(name = "DEVICE_CODE_VALIDITY_SEC")
    private int deviceCodeValiditySeconds;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "clientEntity")
    private Set<ClientClaimRedirect> claimsRedirectUris = new HashSet<>();

    @Lob
    @Column(name = "SOFTWARE_STATEMENT")
    @Convert(converter = JWTStringConverter.class)
    private JWT softwareStatement;

    @Lob
    @Column(name = "CODE_CHALLENGE_METHOD")
    @Convert(converter = PKCEAlgorithmStringConverter.class)
    private PKCEAlgorithm codeChallengeMethod;


    public void setResponseType(ResponseType responseType) {
        Optional<ClientResponseType> clientResponseTypeOptional = responseTypes.stream().filter(r -> r.getResponseType().equals(responseType)).findFirst();
        if(!clientResponseTypeOptional.isPresent()) {
            responseTypes.add(new ClientResponseType(this, responseType));
        }
    }

    public void setResponseType(String responseTypeStr) {
        ResponseType responseType = ResponseType.getResponseType(responseTypeStr);
        setResponseType(responseType);
    }

    public void removeResponseType(ResponseType responseType) {
        Optional<ClientResponseType> clientResponseTypeOptional = responseTypes.stream().filter(r -> r.getResponseType().equals(responseType)).findFirst();
        clientResponseTypeOptional.ifPresent(clientResponseType -> responseTypes.remove(clientResponseType));
    }

    public void setGrantType(GrantType grantType) {
        Optional<ClientGrantType> clientGrantTypeOptional = grantTypes.stream().filter(r -> r.getGrantType().equals(grantType)).findFirst();
        if(!clientGrantTypeOptional.isPresent()) {
            grantTypes.add(new ClientGrantType(this, grantType));
        }
    }

    public void removeGrantType(GrantType grantType) {
        Optional<ClientGrantType> clientGrantTypeOptional = grantTypes.stream().filter(r -> r.getGrantType().equals(grantType)).findFirst();
        clientGrantTypeOptional.ifPresent(clientGrantType -> grantTypes.remove(clientGrantType));
    }

    public boolean hasGrantType(GrantType grantType) {
        return grantTypes.stream().anyMatch(r -> r.getGrantType().equals(grantType));
    }

    public void setScope(String targetScope) {
        Optional<ClientScope> clientScopeOptional = clientScopes.stream().filter(r -> r.getValue().equals(targetScope)).findFirst();
        if(!clientScopeOptional.isPresent()) {
            clientScopes.add(new ClientScope(this, targetScope, null, null, false));
        }
    }

    public void removeScope(String targetScope) {
        Optional<ClientScope> clientScopeOptional = clientScopes.stream().filter(r -> r.getValue().equals(targetScope)).findFirst();
        clientScopeOptional.ifPresent(clientScope -> clientScopes.remove(clientScope));
    }

    public boolean hasScope(String scope) {
        return clientScopes.stream().anyMatch(clientScope -> clientScope.getValue().equals(scope));
    }

    public boolean isAllowRefresh() {
        return hasGrantType(GrantType.REFRESH_TOKEN);
    }
}
