package in.bitanxen.poc.model.user;

import in.bitanxen.poc.model.converter.BooleanToStringConverter;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;

@Entity(name = "TB_SYSTEM_USER_EMAIL")
@Getter
@Setter
@NoArgsConstructor
public class UserEmail {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "USER_EMAIL_MAPPING_ID", nullable = false, unique = true)
    private String userEmailMappingId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "SYSTEM_USER", foreignKey = @ForeignKey(name = "FK_SYSTEM_USER_EMAIL"))
    private SystemUserInfo systemUserInfo;

    @Column(name = "EMAIL_ID", nullable = false, unique = true)
    private String emailId;

    @Column(name = "IS_PRIMARY")
    @Convert(converter = BooleanToStringConverter.class)
    private boolean primary;

    @Column(name = "IS_VERIFIED")
    @Convert(converter = BooleanToStringConverter.class)
    private boolean verified;

    public UserEmail(SystemUserInfo systemUserInfo, String emailId) {
        this.systemUserInfo = systemUserInfo;
        this.emailId = emailId;
    }
}
