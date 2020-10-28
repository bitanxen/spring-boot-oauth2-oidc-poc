package in.bitanxen.poc.config;

import in.bitanxen.poc.util.CommonUtil;
import lombok.extern.log4j.Log4j2;
import org.hibernate.HibernateException;
import org.hibernate.engine.spi.SharedSessionContractImplementor;
import org.hibernate.id.IdentifierGenerator;

import java.io.Serializable;

@Log4j2
public class ApplicationGenericGenerator implements IdentifierGenerator {

    @Override
    public Serializable generate(SharedSessionContractImplementor session, Object object) throws HibernateException {
        return CommonUtil.generateAlphaNumeric(15);
    }


}