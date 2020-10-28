package in.bitanxen.poc.model.authholder;

import in.bitanxen.poc.model.converter.SimpleGrantedAuthorityStringConverter;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@Entity(name = "TB_AUTH_HOLDER_AUTHORITY")
public class AuthenticationHolderAuthority {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "AUTH_HOLDER_ID", nullable = false, unique = true)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "AUTH_HOLDER", nullable = false, foreignKey = @ForeignKey(name = "FK_AUTH_HOLDER_AUTHORITY_AUTH_HOLDER"))
    private AuthenticationHolderEntity authenticationHolderEntity;

    @Convert(converter = SimpleGrantedAuthorityStringConverter.class)
    @Column(name = "GRANTED_AUTHORITY", length = 1000, nullable = false)
    private GrantedAuthority authority;

    public AuthenticationHolderAuthority(AuthenticationHolderEntity authenticationHolderEntity, String authority) {
        this.authenticationHolderEntity = authenticationHolderEntity;
        this.authority = new SimpleGrantedAuthority(authority);
    }
}
