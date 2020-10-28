package in.bitanxen.poc.dto.client;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class ClientRedirectDTO {
    private String clientRedirectId;;
    private String entityId;
    private String clientId;
    private String redirectUri;
}
