package in.bitanxen.poc.service.user;

import in.bitanxen.poc.model.user.UserInfo;

public interface UserService {
    UserInfo getByUsername(String username);
    UserInfo getByUsernameAndClientId(String username, String clientId);
    UserInfo getByEmailAddress(String email);
}
