package in.bitanxen.poc.service.user;

import in.bitanxen.poc.model.client.ClientEntity;
import in.bitanxen.poc.model.statics.SubjectType;
import in.bitanxen.poc.model.user.*;
import in.bitanxen.poc.repository.UserEmailRepository;
import in.bitanxen.poc.repository.UserInfoRepository;
import in.bitanxen.poc.repository.UserPhoneRepository;
import in.bitanxen.poc.service.client.ClientEntityService;
import in.bitanxen.poc.service.oidc.PairwiseIdentifierService;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.Optional;

@Service
@Log4j2
@Transactional
public class UserServiceImpl implements UserService {

    private final UserInfoRepository userInfoRepository;
    private final UserPhoneRepository userPhoneRepository;
    private final UserEmailRepository userEmailRepository;
    private final ClientEntityService clientEntityService;
    private final PairwiseIdentifierService pairwiseIdentifierService;

    public UserServiceImpl(UserInfoRepository userInfoRepository, UserPhoneRepository userPhoneRepository, UserEmailRepository userEmailRepository,
                           ClientEntityService clientEntityService, PairwiseIdentifierService pairwiseIdentifierService) {
        this.userInfoRepository = userInfoRepository;
        this.userPhoneRepository = userPhoneRepository;
        this.userEmailRepository = userEmailRepository;
        this.clientEntityService = clientEntityService;
        this.pairwiseIdentifierService = pairwiseIdentifierService;
    }

    @Override
    public SystemUserInfo getSystemUserByUserCode(String userCode) {
        Optional<SystemUserInfo> userInfoOptional = userInfoRepository.findById(userCode);
        if(!userInfoOptional.isPresent()) {
            throw new UsernameNotFoundException("Usercode ["+userCode+"] not found");
        }
        return userInfoOptional.get();
    }

    @Override
    public SystemUserInfo getSystemUserByUsername(String username) {
        return userInfoRepository.findByPreferredUsername(username);
    }

    @Override
    public UserInfo getUserInfoByUsername(String username) {
        return convertIntoUserInfo(userInfoRepository.findByPreferredUsername(username));
    }

    @Override
    public UserInfo getUserInfoByUsernameAndClientId(String username, String clientId) {
        ClientEntity client = clientEntityService.getClientEntityByClientId(clientId);
        UserInfo userInfo = getUserInfoByUsername(username);

        if (client == null || userInfo == null) {
            return null;
        }

        if (SubjectType.PAIRWISE.equals(client.getSubjectType())) {
            String pairwiseSub = pairwiseIdentifierService.getIdentifier(userInfo, client);
            userInfo.setSub(pairwiseSub);
        }
        return userInfo;
    }

    @Override
    public SystemUserInfo getSystemUserByEmailAddress(String email) {
        UserEmail byEmailId = userEmailRepository.findByEmailId(email);
        if(byEmailId == null) {
            return null;
        }
        return byEmailId.getSystemUserInfo();
    }

    @Override
    public UserInfo getUserInfoByEmailAddress(String email) {
        return convertIntoUserInfo(getSystemUserByEmailAddress(email));
    }

    @Override
    public SystemUserInfo getSystemUserByPhoneNumber(String phone) {
        UserPhone byPhoneNumber = userPhoneRepository.findByPhoneNumber(phone);
        if(byPhoneNumber == null) {
            return null;
        }
        return byPhoneNumber.getSystemUserInfo();
    }

    @Override
    public UserInfo getUserInfoByPhoneNumber(String phone) {
        return convertIntoUserInfo(getSystemUserByPhoneNumber(phone));
    }

    public UserInfo convertIntoUserInfo(SystemUserInfo systemUserInfo) {
        if(systemUserInfo == null) {
            return null;
        }

        UserAddress userPrimaryAddress = systemUserInfo.getUserPrimaryAddress();
        AddressInfo addressInfo = null;
        if(userPrimaryAddress != null) {
            addressInfo = AddressInfo.builder()
                    .addressId(userPrimaryAddress.getAddressId())
                    .formattedAddress(userPrimaryAddress.getFormattedAddress())
                    .streetLine1(userPrimaryAddress.getStreetLine1())
                    .streetLine2(userPrimaryAddress.getStreetLine2())
                    .streetLine3(userPrimaryAddress.getStreetLine3())
                    .city(userPrimaryAddress.getCity())
                    .district(userPrimaryAddress.getDistrict())
                    .region(userPrimaryAddress.getRegion())
                    .landMark(userPrimaryAddress.getLandMark())
                    .state(userPrimaryAddress.getState())
                    .country(userPrimaryAddress.getCountry())
                    .postalCode(userPrimaryAddress.getPostalCode())
                    .build();
        }

        return UserInfo.builder()
                .sub(systemUserInfo.getUserCode())
                .preferredUsername(systemUserInfo.getPreferredUsername())
                .name(systemUserInfo.getName())
                .givenName(systemUserInfo.getGivenName())
                .familyName(systemUserInfo.getFamilyName())
                .middleName(systemUserInfo.getMiddleName())
                .nickName(systemUserInfo.getNickname())
                .picture(null)
                .website(systemUserInfo.getWebsite())
                .emailId(systemUserInfo.getEmail())
                .emailVerified(systemUserInfo.getEmailVerified())
                .phoneNumber(systemUserInfo.getPhoneNumber())
                .phoneVerified(systemUserInfo.getPhoneNumberVerified())
                .gender(systemUserInfo.getGender())
                .birthDate(systemUserInfo.getBirthdate())
                .zoneInfo(systemUserInfo.getZoneInfo())
                .locale(systemUserInfo.getLocale())
                .enabled(systemUserInfo.isEnabled())
                .address(addressInfo)
                .build();
    }
}
