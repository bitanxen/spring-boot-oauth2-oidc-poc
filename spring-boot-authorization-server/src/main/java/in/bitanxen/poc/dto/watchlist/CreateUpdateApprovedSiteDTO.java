package in.bitanxen.poc.dto.watchlist;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
@Builder
public class CreateUpdateApprovedSiteDTO {
    private String userId;
    private String clientId;
    private LocalDateTime timeoutDate;
    private List<String> scopes;
}
