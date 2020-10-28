package in.bitanxen.poc.model.device;

import in.bitanxen.poc.model.authholder.AuthenticationHolderEntity;
import in.bitanxen.poc.model.client.ClientEntity;
import in.bitanxen.poc.model.converter.BooleanToStringConverter;
import in.bitanxen.poc.model.converter.LocalDateTimeAttributeConverter;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@Entity(name = "TB_DEVICE_CODE")
public class DeviceCode {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "DEVICE_CODE_ID", nullable = false, unique = true)
    private String id;

    @Column(name = "DEVICE_CODE", nullable = false)
    private String deviceCode;

    @Column(name = "USER_CODE", nullable = false)
    private String userCode;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "deviceCode")
    private Set<DeviceCodeScope> scopes = new HashSet<>();

    @Column(name = "EXPIRATION")
    @Convert(converter = LocalDateTimeAttributeConverter.class)
    private LocalDateTime expiration;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "CLIENT_ENTITY", foreignKey = @ForeignKey(name = "FK_DEVICE_CODE_CLIENT"))
    private ClientEntity client;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name="TB_DEVICE_CODE_EXTENSION",
            joinColumns=@JoinColumn(name="OWNER_ID")
    )
    @Column(name="PARAM_VALUE")
    @MapKeyColumn(name="PARAM_KEY")
    private Map<String, String> requestParameters = new HashMap<>();

    @Column(name = "IS_APPROVED")
    @Convert(converter = BooleanToStringConverter.class)
    private boolean approved;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "AUTH_HOLDER", foreignKey = @ForeignKey(name = "FK_DEVICE_CODE_AUTH_HOLDER"))
    private AuthenticationHolderEntity authenticationHolder;
}
