package in.bitanxen.poc.model.user;

import in.bitanxen.poc.model.converter.BooleanToStringConverter;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.io.IOUtils;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;
import java.io.IOException;
import java.io.InputStream;

@Entity(name = "TB_SYSTEM_USER_PROFILE_PIC")
@Getter
@Setter
@NoArgsConstructor
@Log4j2
public class UserProfilePicture {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "USER_PROFILE_PIC_MAPPING_ID", nullable = false, unique = true)
    private String userProfilePicId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "SYSTEM_USER", foreignKey = @ForeignKey(name = "FK_SYSTEM_USER_PROFILE_PIC"))
    private SystemUserInfo systemUserInfo;

    @Lob
    @Column(name = "USER_PROFILE_POTO", columnDefinition="BLOB")
    private byte[] photo;

    @Column(name = "ACTIVE")
    @Convert(converter = BooleanToStringConverter.class)
    private boolean active;

    public UserProfilePicture(SystemUserInfo systemUserInfo, InputStream inputStream) throws IOException {
        this.systemUserInfo = systemUserInfo;
        try{
            this.photo = IOUtils.toByteArray(inputStream);
        } catch (Exception e) {
            log.warn("Unable to convert Input Stream to byte array");
        }
    }
}
