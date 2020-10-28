package in.bitanxen.poc.dto.scope;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CreateSystemScopeDTO {
    private String scope;
    private String description;
    private String icon;
    private boolean defaultScope;
    private boolean restrictedScope;
}
