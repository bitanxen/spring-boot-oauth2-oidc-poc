package in.bitanxen.poc.model.authholder;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@Entity(name = "TB_AUTH_HOLDER_RESPONSE")
public class AuthenticationHolderResponseType {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "AUTH_HOLDER_RESPONSE_ID", nullable = false, unique = true)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "AUTH_HOLDER", nullable = false, foreignKey = @ForeignKey(name = "FK_AUTH_HOLDER_RESPONSE_AUTH_HOLDER"))
    private AuthenticationHolderEntity authenticationHolderEntity;

    @Column(name = "RESOURCE", length = 1000, nullable = false)
    private String responseType;

    public AuthenticationHolderResponseType(AuthenticationHolderEntity authenticationHolderEntity, String responseType) {
        this.authenticationHolderEntity = authenticationHolderEntity;
        this.responseType = responseType;
    }
}
