package in.bitanxen.poc.repository;

import in.bitanxen.poc.model.client.ClientEntity;
import in.bitanxen.poc.model.device.DeviceCode;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DeviceCodeRepository extends JpaRepository<DeviceCode, String> {
    DeviceCode findByDeviceCodeAndClient(String code, ClientEntity entity);
}
