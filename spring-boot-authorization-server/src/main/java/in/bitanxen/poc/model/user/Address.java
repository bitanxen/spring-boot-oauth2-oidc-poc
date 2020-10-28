package in.bitanxen.poc.model.user;

import java.io.Serializable;

public interface Address extends Serializable {
    String getAddressId();

    String getFormatted();

    String getStreetAddress();

    String getCity();

    String getDistrict();

    String getRegion();

    String getState();

    String getCountry();

    String getPostalCode();

}
