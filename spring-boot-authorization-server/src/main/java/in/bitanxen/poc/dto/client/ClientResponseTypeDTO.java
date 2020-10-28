package in.bitanxen.poc.dto.client;

import in.bitanxen.poc.model.statics.ResponseType;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class ClientResponseTypeDTO {
    private String clientResponseTypeId;
    private String entityId;
    private String clientId;
    private ResponseType responseType;
}
