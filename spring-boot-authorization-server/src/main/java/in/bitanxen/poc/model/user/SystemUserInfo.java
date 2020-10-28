package in.bitanxen.poc.model.user;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import in.bitanxen.poc.model.converter.BooleanToStringConverter;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity(name = "TB_SYSTEM_USER")
@Getter
@Setter
@NoArgsConstructor
public class SystemUserInfo implements UserInfo {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "USER_CODE", nullable = false, unique = true)
    private String userCode;

    @Column(name="SUB")
    private String sub;

    @Column(name="PREFERRED_USERNAME")
    private String preferredUsername;

    @Column(name="USER_NAME")
    private String name;

    @Column(name="GIVEN_NAME")
    private String givenName;

    @Column(name="FAMILY_NAME")
    private String familyName;

    @Column(name="MIDDLE_NAME")
    private String middleName;

    @Column(name="NICK_NAME")
    private String nickname;

    @Column(name="PROFILE")
    private String profile;

    @Column(name="PICTURE")
    private String picture;

    @Column(name="WEBSITE")
    private String website;

    @Column(name="EMAIL_ID")
    private String email;

    @Column(name="EMAIL_VERIFIED")
    @Convert(converter = BooleanToStringConverter.class)
    private boolean emailVerified;

    @Column(name="PHONE_NUMBER")
    private String phoneNumber;

    @Column(name="PHONE_VERIFIED")
    @Convert(converter = BooleanToStringConverter.class)
    private boolean phoneNumberVerified;

    @Column(name="GENDER")
    private String gender;

    @Column(name="BIRTH_DATE")
    private LocalDate birthdate;

    @Column(name="ZONE_INFO")
    private String zoneinfo;

    @Column(name="LOCALE")
    private String locale;

    @Column(name="ENABLED")
    @Convert(converter = BooleanToStringConverter.class)
    private boolean enabled;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "systemUserInfo")
    private Set<UserAddress> addresses = new HashSet<>();

    @Column(name="CREATED_ON")
    private LocalDateTime createdOn;

    @Column(name="UPDATED_ON")
    private LocalDateTime updatedOn;

    @Override
    public boolean getEmailVerified() {
        return emailVerified;
    }

    @Override
    public boolean getPhoneNumberVerified() {
        return phoneNumberVerified;
    }

    @Override
    public LocalDateTime getCreatedTime() {
        return createdOn;
    }

    @Override
    public LocalDateTime getUpdatedTime() {
        return updatedOn;
    }

    @Override
    public JsonObject toJson() {
        Gson gson = new Gson();
        UserInfo userInfo = this;
        JsonElement jsonElement = gson.toJsonTree(userInfo);
        return jsonElement.getAsJsonObject();
    }

    @Override
    public Set<Address> getAddresses() {
        return new HashSet<>(addresses);
    }
}
