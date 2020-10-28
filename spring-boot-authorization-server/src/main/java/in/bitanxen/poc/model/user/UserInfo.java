package in.bitanxen.poc.model.user;

import com.google.gson.JsonObject;

import java.io.Serializable;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Set;

public interface UserInfo extends Serializable {

    String getSub();

    String getPreferredUsername();

    String getName();

    String getGivenName();

    String getFamilyName();

    String getMiddleName();

    String getNickname();

    String getProfile();

    String getPicture();

    String getWebsite();

    String getEmail();

    boolean getEmailVerified();

    String getPhoneNumber();

    boolean getPhoneNumberVerified();

    String getGender();

    LocalDate getBirthdate();

    String getZoneinfo();

    String getLocale();

    Set<Address> getAddresses();

    boolean isEnabled();

    LocalDateTime getCreatedTime();

    LocalDateTime getUpdatedTime();

    JsonObject toJson();
}
