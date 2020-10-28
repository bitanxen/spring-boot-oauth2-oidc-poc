package in.bitanxen.poc.dto.client;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class ClientContactDTO {
    private String clientContactId;;
    private String entityId;
    private String clientId;
    private String contact;
}
