package in.bitanxen.poc.model.user;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDate;

@Getter
@Setter
@Builder
public class UserInfo {
    private String sub;
    private String preferredUsername;
    private String name;
    private String givenName;
    private String familyName;
    private String middleName;
    private String nickName;
    private String picture;
    private String website;
    private String emailId;
    private boolean emailVerified;
    private String phoneNumber;
    private boolean phoneVerified;
    private Gender gender;
    private LocalDate birthDate;
    private String zoneInfo;
    private String locale;
    private AddressInfo address;
    private boolean enabled;
}
