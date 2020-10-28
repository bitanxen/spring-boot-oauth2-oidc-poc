package in.bitanxen.poc.model.authholder;

import in.bitanxen.poc.model.converter.BooleanToStringConverter;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import javax.persistence.*;
import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "TB_AUTH_HOLDER")
public class AuthenticationHolderEntity {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "AUTH_HOLDER_ID", nullable = false, unique = true)
    private String id;

    @OneToOne(cascade=CascadeType.ALL, fetch = FetchType.LAZY)
    @JoinColumn(name = "AUTHENTICATION", foreignKey = @ForeignKey(name = "FK_AUTH_HOLDER_AUTHENTICATION"))
    private PersistedAuthentication userAuth;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "authenticationHolderEntity")
    private Set<AuthenticationHolderAuthority> authorities = new HashSet<>();

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "authenticationHolderEntity")
    private Set<AuthenticationHolderResource> resources = new HashSet<>();

    @Column(name = "IS_APPROVED")
    @Convert(converter = BooleanToStringConverter.class)
    private boolean approved;

    @Column(name = "REDIRECT_URI")
    private String redirectUri;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "authenticationHolderEntity")
    private Set<AuthenticationHolderResponseType> responseTypes = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name="TB_AUTH_HOLDER_EXTENSION",
            joinColumns=@JoinColumn(name="OWNER_ID")
    )
    @Column(name="EXTENSION_VALUE")
    @MapKeyColumn(name="EXTENSION_KEY")
    //@Convert(converter = SerializableStringConverter.class)
    private Map<String, Serializable> extensions;

    @Column(name = "CLIENT")
    private String clientId;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "authenticationHolderEntity")
    private Set<AuthenticationHolderScope> scope = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name="TB_AUTH_HOLDER_REQ_PARAM",
            joinColumns=@JoinColumn(name="OWNER_ID")
    )
    @Column(name="PARAM_VALUE")
    @MapKeyColumn(name="PARAM_KEY")
    private Map<String, String> requestParameters;

    @Transient
    public OAuth2Authentication getAuthentication() {
        // TODO: memoize this
        return new OAuth2Authentication(createOAuth2Request(), getUserAuth());
    }

    private OAuth2Request createOAuth2Request() {
        Set<GrantedAuthority> grantedAuthorities = authorities.stream().map(AuthenticationHolderAuthority::getAuthority).collect(Collectors.toSet());
        Set<String> grantedScopes = scope.stream().map(AuthenticationHolderScope::getScope).collect(Collectors.toSet());
        Set<String> resourceIds = resources.stream().map(AuthenticationHolderResource::getResource).collect(Collectors.toSet());
        Set<String> grantedResponseTypes = responseTypes.stream().map(AuthenticationHolderResponseType::getResponseType).collect(Collectors.toSet());
        return new OAuth2Request(requestParameters, clientId, grantedAuthorities, approved, grantedScopes, resourceIds, redirectUri, grantedResponseTypes, extensions);
    }

    public void setAuthentication(OAuth2Authentication authentication) {
        OAuth2Request o2Request = authentication.getOAuth2Request();

        Set<AuthenticationHolderAuthority> authenticationHolderAuthorities = o2Request.getAuthorities() == null
                ? null
                : o2Request.getAuthorities().stream()
                                            .map(grantedAuthority -> new AuthenticationHolderAuthority(this, grantedAuthority.getAuthority()))
                                            .collect(Collectors.toSet());

        Set<AuthenticationHolderResource> authenticationHolderResources = o2Request.getResourceIds() == null
                ? null
                : o2Request.getResourceIds().stream()
                                            .map(s -> new AuthenticationHolderResource(this, s))
                                            .collect(Collectors.toSet());

        Set<AuthenticationHolderResponseType> authenticationHolderResponseTypes = o2Request.getResponseTypes() == null
                ? null
                : o2Request.getResponseTypes().stream()
                                            .map(s -> new AuthenticationHolderResponseType(this, s))
                                            .collect(Collectors.toSet());

        Set<AuthenticationHolderScope> authenticationHolderScopes = o2Request.getScope() == null
                ? null
                : o2Request.getScope().stream()
                                    .map(s -> new AuthenticationHolderScope(this, s))
                                    .collect(Collectors.toSet());

        setAuthorities(authenticationHolderAuthorities);
        setClientId(o2Request.getClientId());
        setExtensions(o2Request.getExtensions() == null ? null : new HashMap<>(o2Request.getExtensions()));
        setRedirectUri(o2Request.getRedirectUri());
        setRequestParameters(o2Request.getRequestParameters() == null ? null : new HashMap<>(o2Request.getRequestParameters()));
        setResources(authenticationHolderResources);
        setResponseTypes(authenticationHolderResponseTypes);
        setScope(authenticationHolderScopes);
        setApproved(o2Request.isApproved());

        if (authentication.getUserAuthentication() != null) {
            this.userAuth = new PersistedAuthentication(authentication.getUserAuthentication());
        } else {
            this.userAuth = null;
        }
    }
}
