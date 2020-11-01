package in.bitanxen.poc.repository;

import in.bitanxen.poc.model.user.SystemUserInfo;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserInfoRepository extends JpaRepository<SystemUserInfo, String> {
    SystemUserInfo findByPreferredUsername(String username);
}
