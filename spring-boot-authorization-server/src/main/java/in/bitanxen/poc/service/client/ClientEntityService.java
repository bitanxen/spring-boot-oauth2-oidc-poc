package in.bitanxen.poc.service.client;

import in.bitanxen.poc.dto.client.ClientEntityDTO;
import in.bitanxen.poc.dto.client.CreateUpdateClientEntityDTO;
import in.bitanxen.poc.model.client.ClientEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.Collection;

public interface ClientEntityService extends ClientDetailsService {
    ClientEntity getClientEntityById(String id);
    ClientEntity getClientEntityByClientId(String clientId);
    Collection<ClientEntity> getAllClients();

    @Override
    ClientEntityDTO loadClientByClientId(String clientId) throws OAuth2Exception;

    ClientEntityDTO createClient(CreateUpdateClientEntityDTO createClientEntity);
    void deleteClient(String id);
    ClientEntityDTO updateClient(String id, CreateUpdateClientEntityDTO updateClientEntity, OAuth2Authentication auth);

    String generateClientId();
    String generateClientSecret();

    UserDetails convertClientIntoUser(String clientId, boolean isUriEncoded, boolean isHeartMode, GrantedAuthority grantedAuthority);
}
