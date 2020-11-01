package in.bitanxen.poc.model.user;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class AddressInfo {
    private String addressId;
    private String formattedAddress;
    private String streetLine1;
    private String streetLine2;
    private String streetLine3;
    private String city;
    private String district;
    private String region;
    private String landMark;
    private String state;
    private String country;
    private String postalCode;
}
