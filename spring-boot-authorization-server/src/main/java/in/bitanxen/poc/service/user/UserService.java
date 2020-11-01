package in.bitanxen.poc.service.user;

import in.bitanxen.poc.model.user.SystemUserInfo;
import in.bitanxen.poc.model.user.UserInfo;

public interface UserService {
    SystemUserInfo getSystemUserByUserCode(String userCode);
    SystemUserInfo getSystemUserByUsername(String username);
    UserInfo getUserInfoByUsername(String username);
    UserInfo getUserInfoByUsernameAndClientId(String username, String clientId);
    SystemUserInfo getSystemUserByEmailAddress(String email);
    UserInfo getUserInfoByEmailAddress(String email);
    SystemUserInfo getSystemUserByPhoneNumber(String phone);
    UserInfo getUserInfoByPhoneNumber(String phone);
}
