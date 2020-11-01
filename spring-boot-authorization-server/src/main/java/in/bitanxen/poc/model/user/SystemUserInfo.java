package in.bitanxen.poc.model.user;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import in.bitanxen.poc.model.converter.BooleanToStringConverter;
import in.bitanxen.poc.model.converter.LocalDateTimeAttributeConverter;
import in.bitanxen.poc.model.converter.LocalDateTimeStringConverter;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Entity(name = "TB_SYSTEM_USER")
@Getter
@Setter
@NoArgsConstructor
public class SystemUserInfo {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "USER_CODE", nullable = false, unique = true)
    private String userCode;

    @Column(name="PREFERRED_USERNAME", unique = true, nullable = false)
    private String preferredUsername;

    @Column(name="USER_PASSWORD", unique = true, nullable = false)
    private String password;

    @Column(name="GIVEN_NAME", nullable = false)
    private String givenName;

    @Column(name="FAMILY_NAME")
    private String familyName;

    @Column(name="MIDDLE_NAME")
    private String middleName;

    @Column(name="NICK_NAME")
    private String nickname;

    @Column(name="WEBSITE")
    private String website;

    @Enumerated(EnumType.STRING)
    @Column(name="GENDER", nullable = false)
    private Gender gender;

    @Column(name="BIRTH_DATE")
    private LocalDate birthdate;

    @Column(name="ZONE_INFO")
    private String zoneInfo;

    @Column(name="LOCALE")
    private String locale;

    @Column(name="ENABLED")
    @Convert(converter = BooleanToStringConverter.class)
    private boolean enabled;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "systemUserInfo")
    private Set<UserAddress> addresses = new HashSet<>();

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "systemUserInfo")
    private Set<UserEmail> userEmails = new HashSet<>();

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "systemUserInfo")
    private Set<UserPhone> userPhones = new HashSet<>();

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "systemUserInfo")
    private Set<UserProfilePicture> userProfilePics = new HashSet<>();

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "systemUserInfo")
    private Set<UserCoverPicture> userCoverPics = new HashSet<>();

    @Column(name="CREATED_ON")
    @Convert(converter = LocalDateTimeStringConverter.class)
    private LocalDateTime createdOn;

    @Column(name="UPDATED_ON")
    @Convert(converter = LocalDateTimeStringConverter.class)
    private LocalDateTime updatedOn;

    public String getName() {
        StringBuilder name = new StringBuilder(givenName);
        if(middleName != null && middleName.trim().length() > 0) {
            name.append(" ").append(middleName);
        }
        if(familyName != null && familyName.trim().length() > 0) {
            name.append(" ").append(familyName);
        }
        return name.toString();
    }

    public String getEmail() {
        Optional<String> userEmailOptional = userEmails
                .stream()
                .filter(UserEmail::isPrimary)
                .map(UserEmail::getEmailId)
                .findFirst();
        return userEmailOptional.orElse(null);
    }

    public boolean getEmailVerified() {
        Optional<Boolean> userEmailOptional = userEmails
                .stream()
                .filter(UserEmail::isPrimary)
                .map(UserEmail::isVerified)
                .findFirst();
        return userEmailOptional.orElse(false);
    }

    public String getPhoneNumber() {
        Optional<String> userPhoneOptional = userPhones
                .stream()
                .filter(UserPhone::isPrimary)
                .map(UserPhone::getPhoneNumber)
                .findFirst();
        return userPhoneOptional.orElse(null);
    }

    public boolean getPhoneNumberVerified() {
        Optional<Boolean> userPhoneOptional = userPhones
                .stream()
                .filter(UserPhone::isPrimary)
                .map(UserPhone::isVerified)
                .findFirst();
        return userPhoneOptional.orElse(false);
    }

    public UserAddress getUserPrimaryAddress() {
        return addresses.stream().filter(UserAddress::isPrimary).findAny().orElse(null);
    }

    public Set<UserAddress> getAddresses() {
        return new HashSet<>(addresses);
    }
}
