package in.bitanxen.poc.model.user;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;

@Entity(name = "TB_SYSTEM_USER_ADDRESS")
@Getter
@Setter
@NoArgsConstructor
public class UserAddress implements Address {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "ADDRESS_ID", nullable = false, unique = true)
    private String addressId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "USER_INFO", nullable = false, foreignKey = @ForeignKey(name = "FK_SYSTEM_USER_ADDRESS_USER"))
    private SystemUserInfo systemUserInfo;

    @Column(name = "FORMATTED_ADDRESS")
    private String formatted;

    @Column(name = "STREET_ADDRESS")
    private String streetAddress;

    @Column(name = "CITY")
    private String city;

    @Column(name = "DISTRICT")
    private String district;

    @Column(name = "REGION")
    private String region;

    @Column(name = "STATE")
    private String state;

    @Column(name = "COUNTRY")
    private String country;

    @Column(name = "POSTAL_CODE")
    private String postalCode;

    public UserAddress(SystemUserInfo systemUserInfo, Address address) {
        setSystemUserInfo(systemUserInfo);
        setFormatted(address.getFormatted());
        setStreetAddress(address.getStreetAddress());
        setCity(address.getCity());
        setDistrict(address.getDistrict());
        setRegion(address.getRegion());
        setState(address.getState());
        setCountry(address.getCountry());
        setPostalCode(address.getPostalCode());
    }
}
