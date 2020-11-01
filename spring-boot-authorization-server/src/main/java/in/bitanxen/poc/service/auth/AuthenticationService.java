package in.bitanxen.poc.service.auth;

import in.bitanxen.poc.config.provider.User;

public interface AuthenticationService {
    User getUser(String searchQuery);
}
