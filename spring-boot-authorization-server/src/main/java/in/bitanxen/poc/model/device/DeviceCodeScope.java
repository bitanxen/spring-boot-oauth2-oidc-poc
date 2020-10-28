package in.bitanxen.poc.model.device;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@Entity(name = "TB_DEVICE_CODE_SCOPE")
public class DeviceCodeScope {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "DEVICE_CODE_SCOPE_ID", nullable = false, unique = true)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "DEVICE_CODE", foreignKey = @ForeignKey(name = "FK_DEVICE_CODE_SCOPE_DEVICE_CODE"))
    private DeviceCode deviceCode;

    @Column(name = "SCOPE")
    private String scope;

    public DeviceCodeScope(DeviceCode deviceCode, String scope) {
        this.deviceCode = deviceCode;
        this.scope = scope;
    }
}
