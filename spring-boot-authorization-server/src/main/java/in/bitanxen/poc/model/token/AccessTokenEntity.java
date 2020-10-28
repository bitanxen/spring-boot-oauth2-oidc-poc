package in.bitanxen.poc.model.token;

import com.nimbusds.jwt.JWT;
import in.bitanxen.poc.model.approved.ApprovedSite;
import in.bitanxen.poc.model.authholder.AuthenticationHolderEntity;
import in.bitanxen.poc.model.client.ClientEntity;
import in.bitanxen.poc.model.converter.JWTStringConverter;
import in.bitanxen.poc.model.converter.LocalDateTimeAttributeConverter;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.stream.Collectors;

import static java.time.temporal.ChronoUnit.SECONDS;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "TB_ACCESS_TOKEN")
public class AccessTokenEntity implements OAuth2AccessToken {

    public static final String PARAM_TOKEN_VALUE = "tokenValue";
    public static final String PARAM_CLIENT = "client";
    public static final String PARAM_REFRESH_TOKEN = "refreshToken";
    public static final String PARAM_DATE = "date";
    public static final String PARAM_RESOURCE_SET_ID = "rsid";
    public static final String PARAM_APPROVED_SITE = "approvedSite";
    public static final String PARAM_NAME = "name";
    public static final String ID_TOKEN_FIELD_NAME = "id_token";

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "ACCESS_TOKEN_ID", nullable = false, unique = true)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "CLIENT", foreignKey = @ForeignKey(name = "FK_ACCESS_TOKEN_CLIENT"))
    private ClientEntity client;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "AUTH_HOLDER", foreignKey = @ForeignKey(name = "FK_ACCESS_TOKEN_AUTH_HOLDER"))
    private AuthenticationHolderEntity authenticationHolder; // the authentication that made this access

    @Lob
    @Column(name="TOKEN_VALUE", nullable = false)
    @Convert(converter = JWTStringConverter.class)
    private JWT jwtValue;

    @Column(name = "EXPIRATION")
    @Convert(converter = LocalDateTimeAttributeConverter.class)
    private LocalDateTime expiration;

    @Column(name = "TOKEN_TYPE", nullable = false)
    private String tokenType = OAuth2AccessToken.BEARER_TYPE;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name="REFRESH_TOKEN", foreignKey = @ForeignKey(name = "FK_ACCESS_TOKEN_REFRESH_TOKEN"))
    private RefreshTokenEntity refreshToken;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "accessToken")
    private Set<AccessTokenScope> scopes = new HashSet<>();

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "accessToken")
    private Set<AccessTokenPermission> permissions = new HashSet<>();

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name="APPROVED_SITE", foreignKey = @ForeignKey(name = "FK_ACCESS_TOKEN_APPROVED_SITE"))
    private ApprovedSite approvedSite;

    @Transient
    private Map<String, Object> additionalInformation = new HashMap<>();

    @Override
    public Map<String, Object> getAdditionalInformation() {
        return additionalInformation;
    }

    @Override
    public Set<String> getScope() {
        return scopes.stream().map(AccessTokenScope::getScope).collect(Collectors.toSet());
    }

    @Override
    public RefreshTokenEntity getRefreshToken() {
        return refreshToken;
    }

    @Override
    public String getTokenType() {
        return tokenType;
    }

    @Override
    public boolean isExpired() {
        if(expiration == null) {
            return false;
        }
        return LocalDateTime.now().isAfter(expiration);
    }

    @Override
    public Date getExpiration() {
        if(expiration == null) {
            return null;
        }
        ZonedDateTime zdt = expiration.atZone(ZoneId.systemDefault());
        return Date.from(zdt.toInstant());
    }

    @Override
    public int getExpiresIn() {
        if(expiration == null) {
            return -1;
        }
        if(isExpired()) {
            return 0;
        }
        return (int) SECONDS.between(LocalDateTime.now(), expiration);
    }

    @Override
    public String getValue() {
        return jwtValue.serialize();
    }

    public void setIdToken(JWT idToken) {
        if (idToken != null) {
            additionalInformation.put(ID_TOKEN_FIELD_NAME, idToken.serialize());
        }
    }

    public void setRefreshToken(RefreshTokenEntity refreshToken) {
        this.refreshToken = refreshToken;
    }

    public void setRefreshToken(OAuth2RefreshToken refreshToken) {
        if (!(refreshToken instanceof RefreshTokenEntity)) {
            throw new IllegalArgumentException("Not a storable refresh token entity!");
        }
        setRefreshToken((RefreshTokenEntity)refreshToken);
    }
}
