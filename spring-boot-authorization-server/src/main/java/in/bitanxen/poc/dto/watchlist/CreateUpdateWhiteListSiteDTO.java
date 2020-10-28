package in.bitanxen.poc.dto.watchlist;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class CreateUpdateWhiteListSiteDTO {
    private String clientId;
    private String creator;
    private List<String> scopes;
}
