package in.bitanxen.poc.model.approved;

import in.bitanxen.poc.model.converter.LocalDateTimeAttributeConverter;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@Entity(name = "TB_APPROVED_SITE")
public class ApprovedSite {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "APPROVED_SITE_ID", nullable = false, unique = true)
    private String id;

    @Column(name = "USER_ID")
    private String userId;

    @Column(name = "CLIENT_ID")
    private String clientId;

    @Column(name = "CREATION_DATE")
    @Convert(converter = LocalDateTimeAttributeConverter.class)
    private LocalDateTime creationDate;

    @Column(name = "ACCESS_DATE")
    @Convert(converter = LocalDateTimeAttributeConverter.class)
    private LocalDateTime accessDate;

    @Column(name = "TIMEOUT_DATE")
    @Convert(converter = LocalDateTimeAttributeConverter.class)
    private LocalDateTime timeoutDate;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "approvedSite")
    private Set<ApprovedSiteScope> allowedScopes = new HashSet<>();
}
