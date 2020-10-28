package in.bitanxen.poc.model.client;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@Entity(name = "TB_CLIENT_LOGOUT_REDIRECT")
public class ClientLogoutRedirect {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "CLIENT_LOGOUT_REDIRECT_ID", nullable = false, unique = true)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "CLIENT_ENTITY", nullable = false, foreignKey = @ForeignKey(name = "FK_CLIENT_LOGOUT_REDIRECT_CLIENT"))
    private ClientEntity clientEntity;

    @Column(name = "LOGOUT_REDIRECT_URI", length = 1000, nullable = false)
    private String logoutRedirectUri;

    public ClientLogoutRedirect(ClientEntity clientEntity, String logoutRedirectUri) {
        this.clientEntity = clientEntity;
        this.logoutRedirectUri = logoutRedirectUri;
    }
}
