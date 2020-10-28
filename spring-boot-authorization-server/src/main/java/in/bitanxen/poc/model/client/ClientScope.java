package in.bitanxen.poc.model.client;

import in.bitanxen.poc.model.converter.BooleanToStringConverter;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@Entity(name = "TB_CLIENT_SCOPE")
public class ClientScope {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "CLIENT_SCOPE_ID", nullable = false, unique = true)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "CLIENT_ENTITY", nullable = false, foreignKey = @ForeignKey(name = "FK_CLIENT_SCOPE_CLIENT"))
    private ClientEntity clientEntity;

    @Column(name = "SCOPE_VALUE", length = 100, nullable = false, unique = true)
    private String value;

    @Column(name = "SCOPE_DESCRIPTION", length = 1000)
    private String description;

    @Column(name = "SCOPE_ICON", length = 1000)
    private String icon;

    @Column(name = "DEFAULT_SCOPE", length = 1000, nullable = false)
    @Convert(converter = BooleanToStringConverter.class)
    private boolean defaultScope;

    public ClientScope(ClientEntity clientEntity, String value, String description, String icon, boolean defaultScope) {
        this.clientEntity = clientEntity;
        this.value = value;
        this.description = description;
        this.icon = icon;
        this.defaultScope = defaultScope;
    }
}
