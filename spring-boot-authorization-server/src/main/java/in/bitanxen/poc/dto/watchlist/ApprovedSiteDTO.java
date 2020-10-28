package in.bitanxen.poc.dto.watchlist;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
@Builder
public class ApprovedSiteDTO {
    private String id;
    private String userId;
    private String clientId;
    private LocalDateTime creationDate;
    private LocalDateTime accessDate;
    private LocalDateTime timeoutDate;
    private List<ApprovedSiteScopeDTO> approvedSiteScopes;
}
