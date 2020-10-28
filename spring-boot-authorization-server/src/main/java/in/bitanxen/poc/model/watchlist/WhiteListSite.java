package in.bitanxen.poc.model.watchlist;

import in.bitanxen.poc.model.client.ClientEntity;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@Entity(name = "TB_WHITELISTED_SITE")
public class WhiteListSite {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "WHITEIST_SITE_ID", nullable = false, unique = true)
    private String id;

    @Column(name = "CREATOR_USER_ID")
    private String creatorUserId;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "CLIENT_ENTITY", foreignKey = @ForeignKey(name = "FK_WHITELISTED_SITE_CLIENT"))
    private ClientEntity client;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "whiteListSite")
    private Set<WhiteListSiteScope> allowedScopes = new HashSet<>();
}
