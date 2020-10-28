package in.bitanxen.poc.model.authcode;

import in.bitanxen.poc.model.authholder.AuthenticationHolderEntity;
import in.bitanxen.poc.model.converter.BooleanToStringConverter;
import in.bitanxen.poc.model.converter.LocalDateTimeAttributeConverter;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;
import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "TB_AUTHORIZATION_CODE")
public class AuthorizationCodeEntity {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "AUTHORIZATION_CODE_ID", nullable = false, unique = true)
    private String id;

    @Column(name = "AUTH_CODE", nullable = false)
    private String code;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "AUTH_HOLDER", nullable = false, foreignKey = @ForeignKey(name = "FK_AUTH_HOLDER_AUTH_CODE"))
    private AuthenticationHolderEntity authenticationHolder;

    @Column(name = "ISSUED_AT")
    @Convert(converter = LocalDateTimeAttributeConverter.class)
    private LocalDateTime issuedAt;

    @Column(name = "EXPIRATION")
    @Convert(converter = LocalDateTimeAttributeConverter.class)
    private LocalDateTime expiration;

    @Column(name = "IS_EXPIRED")
    @Convert(converter = BooleanToStringConverter.class)
    private boolean expired;

    public AuthorizationCodeEntity(String code, AuthenticationHolderEntity authenticationHolder, LocalDateTime expiration) {
        this.code = code;
        this.authenticationHolder = authenticationHolder;
        this.issuedAt = LocalDateTime.now();
        this.expiration = expiration;
        this.expired = false;
    }
}
