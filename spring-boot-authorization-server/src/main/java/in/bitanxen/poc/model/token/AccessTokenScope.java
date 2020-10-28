package in.bitanxen.poc.model.token;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@Entity(name = "TB_ACCESS_TOKEN_SCOPE")
public class AccessTokenScope {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "ACCESS_TOKEN_SCOPE_ID", nullable = false, unique = true)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ACCESS_TOKEN", foreignKey = @ForeignKey(name = "FK_ACCESS_TOKEN_SCOPE_ACCESS_TOKEN"))
    private AccessTokenEntity accessToken;

    @Column(name = "SCOPE")
    private String scope;

    public AccessTokenScope(AccessTokenEntity accessToken, String scope) {
        this.accessToken = accessToken;
        this.scope = scope;
    }
}
