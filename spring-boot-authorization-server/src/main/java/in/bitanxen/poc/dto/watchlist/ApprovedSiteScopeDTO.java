package in.bitanxen.poc.dto.watchlist;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Builder
@Getter
@Setter
public class ApprovedSiteScopeDTO {
    private String id;
    private String approvedSiteId;
    private String scope;
}
