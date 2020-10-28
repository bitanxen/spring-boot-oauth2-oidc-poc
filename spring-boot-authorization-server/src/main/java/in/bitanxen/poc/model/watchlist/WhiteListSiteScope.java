package in.bitanxen.poc.model.watchlist;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@Entity(name = "TB_WHITELISTED_SITE_SCOPE")
public class WhiteListSiteScope {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "WHITEIST_SITE_SCOPE_ID", nullable = false, unique = true)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "WHITELIST_SITE", foreignKey = @ForeignKey(name = "FK_SCOPE_WHITELIST_SITE"))
    private WhiteListSite whiteListSite;

    @Column(name = "SCOPE")
    private String scope;

    public WhiteListSiteScope(WhiteListSite whiteListSite, String scope) {
        this.whiteListSite = whiteListSite;
        this.scope = scope;
    }
}
