package in.bitanxen.poc.dto.client;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

@Getter
@Setter
@Builder
public class ClientAuthorityDTO {
    private String clientAuthorityId;
    private String entityId;
    private String clientId;
    private GrantedAuthority authority;
}
