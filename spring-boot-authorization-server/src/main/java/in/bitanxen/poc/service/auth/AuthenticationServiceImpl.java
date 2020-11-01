package in.bitanxen.poc.service.auth;

import in.bitanxen.poc.config.provider.User;
import in.bitanxen.poc.model.user.SystemUserInfo;
import in.bitanxen.poc.service.user.UserService;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.HashSet;
import java.util.Set;

@Service
@Transactional
@Log4j2
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserService userService;

    public AuthenticationServiceImpl(UserService userService) {
        this.userService = userService;
    }

    @Override
    public User getUser(String searchQuery) {
        SystemUserInfo systemUser = userService.getSystemUserByUsername(searchQuery);
        if(systemUser != null) {
            return convertIntoUser(systemUser);
        }

        systemUser = userService.getSystemUserByEmailAddress(searchQuery);
        if(systemUser != null) {
            if(!systemUser.getEmailVerified()) {
                throw new UsernameNotFoundException("User's Email is not verified. Login by username");
            }
            return convertIntoUser(systemUser);
        }

        systemUser = userService.getSystemUserByPhoneNumber(searchQuery);
        if(systemUser != null) {
            if(!systemUser.getPhoneNumberVerified()) {
                throw new UsernameNotFoundException("User's Phone Number is not verified. Login by username");
            }
            return convertIntoUser(systemUser);
        }

        return convertIntoUser(userService.getSystemUserByUserCode(searchQuery));
    }

    private User convertIntoUser(SystemUserInfo systemUserInfo) {
        if(systemUserInfo == null) {
            return null;
        }

        Set<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        return User.builder()
                .userCode(systemUserInfo.getUserCode())
                .username(systemUserInfo.getPreferredUsername())
                .name(systemUserInfo.getName())
                .password(systemUserInfo.getPassword())
                .enabled(systemUserInfo.isEnabled())
                .authorities(authorities)
                .build();
    }
}
