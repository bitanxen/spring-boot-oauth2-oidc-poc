package in.bitanxen.poc.dto.client;

import in.bitanxen.poc.model.statics.GrantType;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class ClientGrantTypeDTO {
    private String clientGrantTypeId;
    private String entityId;
    private String clientId;
    private GrantType grantType;
}
