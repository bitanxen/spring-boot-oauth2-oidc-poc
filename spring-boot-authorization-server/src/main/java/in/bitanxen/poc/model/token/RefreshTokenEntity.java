package in.bitanxen.poc.model.token;

import com.nimbusds.jwt.JWT;
import in.bitanxen.poc.model.authholder.AuthenticationHolderEntity;
import in.bitanxen.poc.model.client.ClientEntity;
import in.bitanxen.poc.model.converter.JWTStringConverter;
import in.bitanxen.poc.model.converter.LocalDateTimeAttributeConverter;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;

import javax.persistence.*;
import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "TB_REFRESH_TOKEN")
public class RefreshTokenEntity implements OAuth2RefreshToken {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "REFRESH_TOKEN_ID", nullable = false, unique = true)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "CLIENT", foreignKey = @ForeignKey(name = "FK_REFRESH_TOKEN_CLIENT"))
    private ClientEntity client;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "AUTH_HOLDER", foreignKey = @ForeignKey(name = "FK_REFRESH_TOKEN_AUTH_HOLDER"))
    private AuthenticationHolderEntity authenticationHolder;

    @Lob
    @Column(name="TOKEN_VALUE", nullable = false)
    @Convert(converter = JWTStringConverter.class)
    private JWT jwt;

    @Column(name = "EXPIRATION")
    @Convert(converter = LocalDateTimeAttributeConverter.class)
    private LocalDateTime expiration;

    @Override
    public String getValue() {
        return jwt.serialize();
    }

    public boolean isExpired() {
        if(expiration == null) {
            return false;
        }
        return LocalDateTime.now().isAfter(expiration);
    }
}
