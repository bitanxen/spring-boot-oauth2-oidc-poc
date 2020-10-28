package in.bitanxen.poc.model.client;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@Entity(name = "TB_CLIENT_ACR_VALUE")
public class ClientACRValue {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "CLIENT_ACR_VALUE_ID", nullable = false, unique = true)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "CLIENT_ENTITY", nullable = false, foreignKey = @ForeignKey(name = "FK_CLIENT_ACR_VALUE_CLIENT"))
    private ClientEntity clientEntity;

    @Column(name = "DEFAULT_ACR_VALUE", length = 1000, nullable = false)
    private String defaultACRValue;

    public ClientACRValue(ClientEntity clientEntity, String defaultACRValue) {
        this.clientEntity = clientEntity;
        this.defaultACRValue = defaultACRValue;
    }
}
