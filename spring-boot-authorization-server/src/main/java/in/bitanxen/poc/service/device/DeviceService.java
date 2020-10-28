package in.bitanxen.poc.service.device;

import in.bitanxen.poc.model.device.DeviceCode;

public interface DeviceService {
    DeviceCode findDeviceCode(String code, String clientId);
    void clearDeviceCode(String code, String clientId);

}
