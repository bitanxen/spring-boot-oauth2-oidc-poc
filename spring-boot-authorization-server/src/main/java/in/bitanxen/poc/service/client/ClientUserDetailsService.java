package in.bitanxen.poc.service.client;

import in.bitanxen.poc.config.bean.ConfigurationProperty;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.stereotype.Service;

@Service
@Log4j2
public class ClientUserDetailsService implements UserDetailsService {

    private static final GrantedAuthority ROLE_CLIENT = new SimpleGrantedAuthority("ROLE_CLIENT");

    private final ClientEntityService clientEntityService;
    private final ConfigurationProperty configurationProperty;

    public ClientUserDetailsService(ClientEntityService clientEntityService, ConfigurationProperty configurationProperty) {
        this.clientEntityService = clientEntityService;
        this.configurationProperty = configurationProperty;
    }

    @Override
    public UserDetails loadUserByUsername(String clientId) throws UsernameNotFoundException {
        try {
            return clientEntityService.convertClientIntoUser(clientId, false, configurationProperty.isHeartMode(), ROLE_CLIENT);
        } catch (InvalidClientException e) {
            throw new UsernameNotFoundException("Client not found: " + clientId);
        }
    }
}
