package in.bitanxen.poc.dto.client;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class ClientScopeDTO {
    private String clientScopeId;
    private String entityId;
    private String clientId;
    private String scope;
    private String description;
    private String icon;
    private boolean defaultScope;
}
