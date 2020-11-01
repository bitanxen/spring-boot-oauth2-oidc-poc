package in.bitanxen.poc.repository;

import in.bitanxen.poc.model.user.UserPhone;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserPhoneRepository extends JpaRepository<UserPhone, String> {
    UserPhone findByPhoneNumber(String phoneNumber);
}
