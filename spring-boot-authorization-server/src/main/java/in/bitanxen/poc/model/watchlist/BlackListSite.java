package in.bitanxen.poc.model.watchlist;

import in.bitanxen.poc.model.converter.BooleanToStringConverter;
import in.bitanxen.poc.model.converter.LocalDateTimeAttributeConverter;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;
import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@Entity(name = "TB_BLACKLISTED_SITE")
public class BlackListSite {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "BLACKLIST_ID", nullable = false, unique = true)
    private String id;

    @Column(name = "SITE_URI")
    private String uri;

    @Column(name = "ENABLED")
    @Convert(converter = BooleanToStringConverter.class)
    private boolean enabled;

    @Column(name = "CREATED_AT")
    @Convert(converter = LocalDateTimeAttributeConverter.class)
    private LocalDateTime createdAt;


}
