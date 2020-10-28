package in.bitanxen.poc.model.client;

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
@Entity(name = "TB_CLIENT_AUTHORITY")
public class ClientGrantedAuthority {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "CLIENT_AUTHORITY_ID", nullable = false, unique = true)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "CLIENT_ENTITY", nullable = false, foreignKey = @ForeignKey(name = "FK_CLIENT_AUTHORITY_CLIENT"))
    private ClientEntity clientEntity;

    @Convert(converter = SimpleGrantedAuthorityStringConverter.class)
    @Column(name = "GRANTED_AUTHORITY", length = 1000, nullable = false)
    private GrantedAuthority authority;

    public ClientGrantedAuthority(ClientEntity clientEntity, String authority) {
        this.clientEntity = clientEntity;
        this.authority = new SimpleGrantedAuthority(authority);
    }
}
