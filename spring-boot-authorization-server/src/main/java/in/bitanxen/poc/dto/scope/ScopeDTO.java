package in.bitanxen.poc.dto.scope;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class ScopeDTO {
    private String scopeId;
    private String scopeValue;
    private String scopeDescription;
    private String scopeIcon;
    private boolean isDefault;
    private boolean isRestricted;
}
