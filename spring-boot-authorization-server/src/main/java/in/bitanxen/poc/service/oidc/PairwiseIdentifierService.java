package in.bitanxen.poc.service.oidc;

import in.bitanxen.poc.model.client.ClientEntity;
import in.bitanxen.poc.model.user.UserInfo;

public interface PairwiseIdentifierService {
    String getIdentifier(UserInfo userInfo, ClientEntity client);
}
