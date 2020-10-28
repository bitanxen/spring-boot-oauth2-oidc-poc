package in.bitanxen.poc.model.user;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Entity(name = "TB_PAIRWISE_IDENTIFIER")
@Getter
@Setter
@NoArgsConstructor
public class PairwiseIdentifier {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "PAIRWISE_IDENTIFIER_ID", nullable = false, unique = true)
    private String id;

    @Column(name = "IDENTIFIER")
    private String identifier;

    @Column(name = "USERSUB")
    private String userSub;

    @Column(name = "SECTOR_IDENTIFIER")
    private String sectorIdentifier;

    public PairwiseIdentifier(String identifier, String userSub, String sectorIdentifier) {
        this.identifier = identifier;
        this.userSub = userSub;
        this.sectorIdentifier = sectorIdentifier;
    }
}
