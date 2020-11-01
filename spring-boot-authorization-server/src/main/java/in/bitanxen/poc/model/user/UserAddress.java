package in.bitanxen.poc.model.user;

import in.bitanxen.poc.model.converter.BooleanToStringConverter;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;

@Entity(name = "TB_SYSTEM_USER_ADDRESS")
@Getter
@Setter
@NoArgsConstructor
public class UserAddress {

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

    @Column(name = "STREET_LINE_1", nullable = false)
    private String streetLine1;

    @Column(name = "STREET_LINE_2")
    private String streetLine2;

    @Column(name = "STREET_LINE_3")
    private String streetLine3;

    @Column(name = "CITY")
    private String city;

    @Column(name = "DISTRICT")
    private String district;

    @Column(name = "REGION")
    private String region;

    @Column(name = "LAND_MARK")
    private String landMark;

    @Column(name = "STATE")
    private String state;

    @Column(name = "COUNTRY", nullable = false)
    private String country;

    @Column(name = "POSTAL_CODE", nullable = false)
    private String postalCode;

    @Column(name = "IS_PRIMARY")
    @Convert(converter = BooleanToStringConverter.class)
    private boolean primary;

    public String getFormattedAddress() {
        StringBuilder stringBuilder = new StringBuilder(streetLine1.trim());
        if(streetLine2 != null && streetLine2.trim().length() > 0) {
            stringBuilder.append(",\n").append(streetLine2.trim());
        }
        if(streetLine3 != null && streetLine3.trim().length() > 0) {
            stringBuilder.append(",\n").append(streetLine3.trim());
        }
        if(city != null && city.trim().length() > 0) {
            stringBuilder.append(",\nCity: ").append(city.trim());
        }
        if(district != null && district.trim().length() > 0) {
            stringBuilder.append("\nDistrict: ").append(district.trim());
        }
        if(state != null && state.trim().length() > 0) {
            stringBuilder.append("\nState: ").append(state.trim());
        }
        stringBuilder.append("\nCountry: ").append(country.trim());
        stringBuilder.append("\nPostal Code: ").append(postalCode.trim());
        return stringBuilder.toString();
    }
}
