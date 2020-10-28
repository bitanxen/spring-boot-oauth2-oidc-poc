package in.bitanxen.poc.model.client;

import in.bitanxen.poc.model.statics.GrantType;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@Entity(name = "TB_CLIENT_GRANT_TYPE")
public class ClientGrantType {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "CLIENT_GRANT_TYPE_ID", nullable = false, unique = true)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "CLIENT_ENTITY", nullable = false, foreignKey = @ForeignKey(name = "FK_CLIENT_GRANT_TYPE_CLIENT"))
    private ClientEntity clientEntity;

    @Enumerated(value = EnumType.STRING)
    @Column(name = "GRANT_TYPE", length = 1000, nullable = false)
    private GrantType grantType;

    public ClientGrantType(ClientEntity clientEntity, GrantType grantType) {
        this.clientEntity = clientEntity;
        this.grantType = grantType;
    }
}
