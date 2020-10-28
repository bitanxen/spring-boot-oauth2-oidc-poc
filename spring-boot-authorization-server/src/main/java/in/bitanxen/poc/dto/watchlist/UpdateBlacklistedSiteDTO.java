package in.bitanxen.poc.dto.watchlist;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdateBlacklistedSiteDTO {
    private String siteUrl;
    private boolean enabled;
}
