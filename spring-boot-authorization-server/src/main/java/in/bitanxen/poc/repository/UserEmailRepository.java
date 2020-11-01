package in.bitanxen.poc.repository;

import in.bitanxen.poc.model.user.UserEmail;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserEmailRepository extends JpaRepository<UserEmail, String> {
    UserEmail findByEmailId(String emailId);
}
