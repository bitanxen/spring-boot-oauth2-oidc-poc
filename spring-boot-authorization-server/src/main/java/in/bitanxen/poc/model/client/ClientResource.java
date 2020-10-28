package in.bitanxen.poc.model.client;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@Entity(name = "TB_CLIENT_RESOURCE")
public class ClientResource {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "CLIENT_RESOURCE_ID", nullable = false, unique = true)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "CLIENT_ENTITY", nullable = false, foreignKey = @ForeignKey(name = "FK_CLIENT_RESOURCE_CLIENT"))
    private ClientEntity clientEntity;

    @Column(name = "RESOURCE_ID", length = 1000, nullable = false)
    private String resourceId;

    public ClientResource(ClientEntity clientEntity, String resourceId) {
        this.clientEntity = clientEntity;
        this.resourceId = resourceId;
    }
}
