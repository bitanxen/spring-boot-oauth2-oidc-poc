package in.bitanxen.poc.model.client;

import in.bitanxen.poc.model.statics.ResponseType;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@Entity(name = "TB_CLIENT_RESPONSE_TYPE")
public class ClientResponseType {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "CLIENT_RESPONSE_TYPE_ID", nullable = false, unique = true)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "CLIENT_ENTITY", nullable = false, foreignKey = @ForeignKey(name = "FK_CLIENT_RESPONSE_TYPE_CLIENT"))
    private ClientEntity clientEntity;

    @Enumerated(value = EnumType.STRING)
    @Column(name = "RESPONSE_TYPE", length = 1000, nullable = false)
    private ResponseType responseType;

    public ClientResponseType(ClientEntity clientEntity, ResponseType responseType) {
        this.clientEntity = clientEntity;
        this.responseType = responseType;
    }
}
