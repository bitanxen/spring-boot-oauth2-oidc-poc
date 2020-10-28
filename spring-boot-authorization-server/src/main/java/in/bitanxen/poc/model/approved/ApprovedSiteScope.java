package in.bitanxen.poc.model.approved;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@Entity(name = "TB_APPROVED_SITE_SCOPE")
public class ApprovedSiteScope {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "APPROVED_SITE_SCOPE_ID", nullable = false, unique = true)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name="APPROVED_SITE", foreignKey = @ForeignKey(name = "FK_APPROVED_SITE_SCOPE_APPROVED_SITE"))
    private ApprovedSite approvedSite;

    @Column(name = "SCOPE")
    private String scope;

    public ApprovedSiteScope(ApprovedSite approvedSite, String scope) {
        this.approvedSite = approvedSite;
        this.scope = scope;
    }
}
