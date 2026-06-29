package io.github.artshp.jwhisper.relay.util;

import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

/**
 * Bridge giving access to Spring context.
 */
@Component
public class SpringContextBridge implements ApplicationContextAware {

    /**
     * Spring application context
     */
    private static ApplicationContext context;

    /**
     * Get a bean from Spring context.
     * @param beanClass bean class type
     * @return bean from context
     * @param <T> bean type
     * @see ApplicationContext#getBean(Class)
     */
    public static <T> T getBean(Class<T> beanClass) {
        return context.getBean(beanClass);
    }

    /**
     * Create a new spring context bridge.
     */
    public SpringContextBridge() {
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) {
        context = applicationContext;
    }
}
