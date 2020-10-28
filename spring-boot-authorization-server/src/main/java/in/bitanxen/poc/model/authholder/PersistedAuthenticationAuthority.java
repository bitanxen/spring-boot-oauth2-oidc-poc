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
@Entity(name = "TB_SAVED_USER_AUTH_AUTHORITY")
public class PersistedAuthenticationAuthority {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "AUTH_AUTHORITY_ID", nullable = false, unique = true)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "AUTHENTICATION", nullable = false, foreignKey = @ForeignKey(name = "FK_AUTH_AUTHORITY_AUTHENTICATION"))
    private PersistedAuthentication persistedAuthentication;

    @Convert(converter = SimpleGrantedAuthorityStringConverter.class)
    @Column(name = "GRANTED_AUTHORITY", length = 1000, nullable = false)
    private GrantedAuthority authority;

    public PersistedAuthenticationAuthority(PersistedAuthentication persistedAuthentication, String authority) {
        this.persistedAuthentication = persistedAuthentication;
        this.authority = new SimpleGrantedAuthority(authority);
    }
}
