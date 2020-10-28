package in.bitanxen.poc.model.scope;

import in.bitanxen.poc.model.converter.BooleanToStringConverter;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@Entity(name = "TB_SYSTEM_SCOPE")
public class SystemScope {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "SYSTEM_SCOPE_ID", nullable = false, unique = true)
    private String id;

    @Column(name = "SCOPE_VALUE", length = 1000, nullable = false, unique = true)
    private String value;

    @Column(name = "SCOPE_DESCRIPTION", length = 1000, nullable = false)
    private String description;

    @Column(name = "SCOPE_ICON", length = 1000, nullable = false)
    private String icon;

    @Column(name = "DEFAULT_SCOPE", length = 1000, nullable = false)
    @Convert(converter = BooleanToStringConverter.class)
    private boolean defaultScope;

    @Column(name = "RESTRICTED_SCOPE", length = 1000, nullable = false)
    @Convert(converter = BooleanToStringConverter.class)
    private boolean restricted;

    public SystemScope(String value, String description, String icon, boolean defaultScope, boolean restricted) {
        this.value = value;
        this.description = description;
        this.icon = icon;
        this.defaultScope = defaultScope;
        this.restricted = restricted;
    }

}
