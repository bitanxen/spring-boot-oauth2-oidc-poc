package in.bitanxen.poc.model.user;

import in.bitanxen.poc.model.converter.BooleanToStringConverter;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;

@Entity(name = "TB_SYSTEM_USER_PHONE")
@Getter
@Setter
@NoArgsConstructor
public class UserPhone {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "USER_PHONE_MAPPING_ID", nullable = false, unique = true)
    private String userPhoneMappingId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "SYSTEM_USER", foreignKey = @ForeignKey(name = "FK_SYSTEM_USER_PHONE"))
    private SystemUserInfo systemUserInfo;

    @Column(name = "PHONE_NUMBER", nullable = false, unique = true)
    private String phoneNumber;

    @Column(name = "IS_PRIMARY")
    @Convert(converter = BooleanToStringConverter.class)
    private boolean primary;

    @Column(name = "IS_VERIFIED")
    @Convert(converter = BooleanToStringConverter.class)
    private boolean verified;

    public UserPhone(SystemUserInfo systemUserInfo, String phoneNumber) {
        this.systemUserInfo = systemUserInfo;
        this.phoneNumber = phoneNumber;
    }
}
