package in.bitanxen.poc.service.device;

import in.bitanxen.poc.model.client.ClientEntity;
import in.bitanxen.poc.model.device.DeviceCode;
import in.bitanxen.poc.repository.DeviceCodeRepository;
import in.bitanxen.poc.service.client.ClientEntityService;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Service
@Log4j2
@Transactional
public class DeviceServiceImpl implements DeviceService {

    private final DeviceCodeRepository deviceCodeRepository;
    private final ClientEntityService clientEntityService;

    public DeviceServiceImpl(DeviceCodeRepository deviceCodeRepository, ClientEntityService clientEntityService) {
        this.deviceCodeRepository = deviceCodeRepository;
        this.clientEntityService = clientEntityService;
    }

    @Override
    public DeviceCode findDeviceCode(String code, String clientId) {
        ClientEntity clientEntity = clientEntityService.getClientEntityByClientId(clientId);
        return deviceCodeRepository.findByDeviceCodeAndClient(code, clientEntity);
    }

    @Override
    public void clearDeviceCode(String code, String clientId) {
        DeviceCode deviceCode = findDeviceCode(code, clientId);
        deviceCodeRepository.delete(deviceCode);
    }
}
