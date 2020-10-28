package in.bitanxen.poc.dto.client;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class ClientClaimsRedirectURIDTO {
    private String clientClaimRedirectId;
    private String entityId;
    private String clientId;
    private String claimsRedirectUri;
}
